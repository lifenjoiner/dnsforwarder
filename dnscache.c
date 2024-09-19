#include <stdio.h>
#include <string.h>
#include <time.h>
#include "dnscache.h"
#include "dnsgenerator.h"
#include "utils.h"
#include "rwlock.h"
#include "cacheht.h"
#include "cachettlcrtl.h"
#include "logs.h"
#include "timedtask.h"
#include "domainstatistic.h"

#define CACHE_VERSION   23

#define CACHE_END   '\x0A'
#define CACHE_START '\xFF'

static BOOL             Inited = FALSE;
static BOOL             CacheParallel = FALSE;

static RWLock           CacheLock = NULL_RWLOCK;

static FileHandle       CacheFileHandle = INVALID_FILE;
static MappingHandle    CacheMappingHandle = INVALID_MAP;
static char             *MapStart = NULL;
static BOOL             MemoryCache = FALSE;

static int32_t          CacheSize;
static BOOL             IgnoreTTL;

static int32_t          *CacheCount;

static volatile int32_t *CacheEnd; /* Offset */

static CacheHT          *CacheInfo;

static CacheTtlCtrl     *TtlCtrl = NULL;

struct _Header{
    uint32_t    Ver;
    int32_t     CacheSize;
    int32_t     End;
    int32_t     CacheCount;
    CacheHT     ht;
    char        Comment[128 - sizeof(uint32_t) - sizeof(int32_t) - sizeof(int32_t) - sizeof(int32_t) - sizeof(CacheHT)];
};

static void DNSCacheTTLCountdown_Task(void *Unused, void *Unused2)
{
    BOOL        GotMutex = FALSE;

    const Array *ChunkList = &(CacheInfo->NodeChunk);
    int         loop = ChunkList->Used - 1;
    Cht_Node    *Node = (Cht_Node *)Array_GetBySubscript(ChunkList, loop);

    time_t      CurrentTime = time(NULL);

    while( Node != NULL )
    {
        if( Node->TTL > 0 )
        {
            if( CurrentTime - Node->TimeAdded >= Node->TTL )
            {
                if(GotMutex == FALSE)
                {
                    RWLock_WrLock(CacheLock);
                    GotMutex = TRUE;
                }

                Node->TTL = 0;

                *(char *)(MapStart + Node->Offset) = 0xFD;

                CacheHT_RemoveFromSlot(CacheInfo, loop, Node);

                --(*CacheCount);

            }
        }

        Node = (Cht_Node *)Array_GetBySubscript(ChunkList, --loop);
    }

    if(GotMutex == TRUE)
    {
        if( ChunkList->Used == 0 )
        {
            (*CacheEnd) = sizeof(struct _Header);
        } else {
            Node = (Cht_Node *)Array_GetBySubscript(ChunkList, ChunkList->Used - 1);
            (*CacheEnd) = Node->Offset + Node->Length;
        }

        RWLock_UnWLock(CacheLock);
    }
}

static BOOL IsReloadable(void)
{
    const struct _Header *Header = (struct _Header *)MapStart;

    if( Header->Ver != CACHE_VERSION )
    {
        ERRORMSG("The existing cache is not compatible with this version of program.\n");
        return FALSE;
    }

    if( Header->CacheSize != CacheSize )
    {
        ERRORMSG("The size of the existing cache and the value of `CacheSize' should be equal.\n");
        return FALSE;
    }

    return TRUE;
}

static void ReloadCache(void)
{
    struct _Header  *Header = (struct _Header *)MapStart;

    INFO("Reloading the cache ...\n");

    CacheInfo = &(Header->ht);

    CacheHT_ReInit(CacheInfo, MapStart, CacheSize);

    CacheEnd = &(Header->End);
    CacheCount = &(Header->CacheCount);

    INFO("Cache reloaded, containing %d entries for %d items.\n", CacheInfo->NodeChunk.Used, (*CacheCount));
}

static void CreateNewCache(void)
{
    struct _Header  *Header = (struct _Header *)MapStart;

    memset(MapStart, 0, CacheSize);

    Header->Ver = CACHE_VERSION;
    Header->CacheSize = CacheSize;
    Header->CacheCount = 0;
    CacheEnd = &(Header->End);
    *CacheEnd = sizeof(struct _Header);
    memset(Header->Comment, 0, sizeof(Header->Comment));
    strncpy(Header->Comment,
            "\nDo not edit this file.\n",
            sizeof(Header->Comment)
            );

    Header->Comment[sizeof(Header->Comment) - 1] = '\0';

    CacheInfo = &(Header->ht);
    CacheCount = &(Header->CacheCount);

    CacheHT_Init(CacheInfo, MapStart, CacheSize);

}

static int InitCacheInfo(ConfigFileInfo *ConfigInfo, BOOL Reload)
{
    if( Reload == TRUE )
    {
        if( IsReloadable() )
        {
            ReloadCache();
        } else {
            if( ConfigGetBoolean(ConfigInfo, "OverwriteCache") == FALSE )
            {
                return -1;
            } else {
                CreateNewCache();
                INFO("The existing cache has been overwritten.\n");
            }
        }
    } else {
        CreateNewCache();
    }
    return 0;
}

static void DNSCache_Cleanup(void)
{
    if( CacheFileHandle != INVALID_FILE )
    {
        if(CacheMappingHandle != INVALID_MAP)
        {
            UNMAP_FILE(MapStart, CacheSize);
            DESTROY_MAPPING(CacheMappingHandle);
        }
        CLOSE_FILE(CacheFileHandle);
    }
    if( TtlCtrl != NULL)
    {
        CacheTtlCrtl_Free(TtlCtrl);
    }
    if( MemoryCache && MapStart != NULL )
    {
        CacheHT_Free(CacheInfo);
        SafeFree(MapStart);
    }
    RWLock_Destroy(CacheLock);
}

int DNSCache_Init(ConfigFileInfo *ConfigInfo)
{
    int         _CacheSize = ConfigGetInt32(ConfigInfo, "CacheSize");
    const char  *CacheFile = ConfigGetRawString(ConfigInfo, "CacheFile");
    int         InitCacheInfoState;

    int         OverrideTTL;
    int         TTLMultiple;

    StringList  *ctc = ConfigGetStringList(ConfigInfo, "CacheControl");

    if( ConfigGetBoolean(ConfigInfo, "UseCache") == FALSE )
    {
        return 0;
    }

    CacheParallel = ConfigGetBoolean(ConfigInfo, "CacheParallel");

    IgnoreTTL = ConfigGetBoolean(ConfigInfo, "IgnoreTTL");

    OverrideTTL = ConfigGetInt32(ConfigInfo, "OverrideTTL");
    TTLMultiple = ConfigGetInt32(ConfigInfo, "MultipleTTL");

    if( ctc != NULL || OverrideTTL > -1 || TTLMultiple > 1 )
    {
        TtlCtrl = malloc(sizeof(CacheTtlCtrl));
        if( TtlCtrl == NULL || CacheTtlCrtl_Init(TtlCtrl) != 0 )
        {
            return -1;
        }
    }

    atexit(DNSCache_Cleanup);

    if( ctc != NULL )
    {
        CacheTtlCrtl_Add_From_StringList(TtlCtrl, ctc);
    }

    if( OverrideTTL > -1 )
    {
        CacheTtlCrtl_Add(TtlCtrl, "*", TTL_STATE_FIXED, 1, OverrideTTL, TRUE);
    } else {
        if( TTLMultiple < 1 )
        {
            ERRORMSG("Invalid `MultipleTTL'.\n");
        } else if( TTLMultiple > 1 ){
            CacheTtlCrtl_Add(TtlCtrl, "*", TTL_STATE_VARIABLE, TTLMultiple, 0, TRUE);
        }
    }

    CacheSize = ROUND_UP(_CacheSize, 8);

    if( CacheSize < 102400 )
    {
        ERRORMSG("Cache size must not less than 102400 bytes.\n");
        return 1;
    }

    if( ConfigGetBoolean(ConfigInfo, "MemoryCache") == TRUE )
    {
        MemoryCache = TRUE;
        MapStart = SafeMalloc(CacheSize);

        if( MapStart == NULL )
        {
            ERRORMSG("Cache initializing failed.\n");
            return 2;
        }

        InitCacheInfoState = InitCacheInfo(ConfigInfo, FALSE);
    } else {
        BOOL FileExists;

        INFO("Cache File : %s\n", CacheFile);

        FileExists = FileIsReadable(CacheFile);

        CacheFileHandle = OPEN_FILE(CacheFile);
        if(CacheFileHandle == INVALID_FILE)
        {
            int ErrorNum = GET_LAST_ERROR();
            char ErrorMessage[320];

            GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

            ERRORMSG("Cache initializing failed : %d : %s.\n", ErrorNum, ErrorMessage);

            return 3;
        }

        CacheMappingHandle = CREATE_FILE_MAPPING(CacheFileHandle, CacheSize);
        if(CacheMappingHandle == INVALID_MAP)
        {
            int ErrorNum = GET_LAST_ERROR();
            char ErrorMessage[320];

            GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

            ERRORMSG("Cache initializing failed : %d : %s.\n", ErrorNum, ErrorMessage);
            return 4;
        }

        MapStart = (char *)MPA_FILE(CacheMappingHandle, CacheSize);
        if(MapStart == INVALID_MAPPING_FILE)
        {
            int ErrorNum = GET_LAST_ERROR();
            char ErrorMessage[320];

            GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

            ERRORMSG("Cache initializing failed : %d : %s.\n", ErrorNum, ErrorMessage);
            return 5;
        }

        if( FileExists == FALSE )
        {
            InitCacheInfoState = InitCacheInfo(ConfigInfo, FALSE);
        } else {
            InitCacheInfoState = InitCacheInfo(ConfigInfo, ConfigGetBoolean(ConfigInfo, "ReloadCache"));
        }
    }

    if( InitCacheInfoState != 0 )
    {
        return 6;
    }

    RWLock_Init(CacheLock);

    Inited = TRUE;

    if( !IgnoreTTL )
    {
        TimedTask_Add(TRUE,
                      FALSE,
                      59000,
                      (TaskFunc)DNSCacheTTLCountdown_Task,
                      NULL,
                      NULL,
                      TRUE
                      );
    }

    return 0;
}

BOOL Cache_IsInited(void)
{
    return Inited;
}

static int32_t DNSCache_GetAviliableChunk(uint32_t Length, Cht_Node **Out)
{
    int32_t NodeNumber;
    Cht_Node    *Node;
    uint32_t    RoundedLength = ROUND_UP(Length, 4);

    BOOL    NewCreated;

    NodeNumber = CacheHT_FindUnusedNode(CacheInfo, RoundedLength, &Node, MapStart + (*CacheEnd) + RoundedLength, &NewCreated);
    if( NodeNumber >= 0 )
    {
        if( NewCreated == TRUE )
        {
            Node->Offset = (*CacheEnd);
            (*CacheEnd) += RoundedLength;
        }

        memset(MapStart + Node->Offset + Length, 0xFE, RoundedLength - Length);

        *Out = Node;
        return NodeNumber;
    } else {
        *Out = NULL;
        return -1;
    }

}

static Cht_Node *DNSCache_FindFromCache(const char *Content, size_t Length, Cht_Node *Start, time_t CurrentTime)
{
    Cht_Node *Node = Start;

    do{
        Node = CacheHT_Get(CacheInfo, Content, Node, NULL);
        if( Node == NULL )
        {
            return NULL;
        }

        if( IgnoreTTL == TRUE || (CurrentTime - Node->TimeAdded < Node->TTL) )
        {
            if( memcmp(Content, MapStart + Node->Offset + 1, Length) == 0 )
            {
                return Node;
            }
        }

    } while( TRUE );

}

static uint32_t DNSCache_CacheMinTTL(const char *Content, size_t Length, uint32_t NewTTL, time_t CurrentTime)
{
    uint32_t RecordTTL = NewTTL;
    Cht_Node *Node = NULL;

    /* Get the smallest, in case of not equal. */
    while( (Node = DNSCache_FindFromCache(Content, Length, Node, CurrentTime)) != NULL )
    {
        uint32_t TTL = Node->TTL - (CurrentTime - Node->TimeAdded);
        if( RecordTTL > TTL )
        {
            RecordTTL = TTL;
        }
    }

    Node = NULL;
    while( (Node = DNSCache_FindFromCache(Content, Length, Node, CurrentTime)) != NULL )
    {
        Node->TTL = RecordTTL;
        Node->TimeAdded = CurrentTime;
    }

    return RecordTTL;
}

/* Item: \xFFStrName\x01HexType\x01HexClass\x00(R)Data
   ht: StrName\x01HexType\x01HexClass, NtcTriplet
   https://tools.ietf.org/html/rfc1035 */
static int DNSCache_AddAItemToCache(DnsSimpleParserIterator *i,
                                    time_t CurrentTime,
                                    const CtrlContent *InfectedTtlContent
                                    )
{
    /* used to store cache data temporarily, TODO: no bounds checking here */
    char            Buffer[512];
    char            *Item = Buffer + 1;
    int             Length;

    /* Iterator of `Buffer' */
    char            *BufferItr;

    const CtrlContent   *TtlContent;

    /* Assign start byte of the cache */
    Buffer[0] = CACHE_START;

    /* Assign the name of the cache */
    if( i->GetName(i, Item, sizeof(Buffer) -1) < 0 )
    {
        return -1;
    }

    /* Detemine which TTL scheme will be used */
    if( InfectedTtlContent != NULL )
    {
        switch( InfectedTtlContent->Infection )
        {
            default:
            case TTL_CTRL_INFECTION_AGGRESSIVLY:
                TtlContent = InfectedTtlContent;
                break;

            case TTL_CTRL_INFECTION_PASSIVLY:
                TtlContent = CacheTtlCrtl_Get(TtlCtrl, Item);
                if( TtlContent == NULL )
                {
                    TtlContent = InfectedTtlContent;
                }
                break;

            case TTL_CTRL_INFECTION_NONE:
                TtlContent = CacheTtlCrtl_Get(TtlCtrl, Item);
                break;
        }
    } else {
        TtlContent = CacheTtlCrtl_Get(TtlCtrl, Item);
    }

    /* Jump just over the name, right at '\0' */
    BufferItr = Item + strlen(Item);
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -2;
    }

    /* Set record type and class */
    BufferItr += snprintf(BufferItr,
                          sizeof(Buffer) - (BufferItr - Buffer),
                          "\1%X\1%X",
                          i->Type,
                          i->Klass
                          );
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -3;
    }

    /* End of name\1type\1class triple */
    BufferItr++;
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -4;
    }

    /* Generate data and store them */
    Length = i->ToCacheData(i,
                            BufferItr,
                            sizeof(Buffer) - (BufferItr - Buffer)
                            );
    if( Length <= 0 )
    {
        return -5;
    }
    BufferItr += Length;
    if( BufferItr >= Buffer + sizeof(Buffer) )
    {
        return -6;
    }

    /* The whole cache data generating completed */

    /* Add the cache item to the main cache zone below */

    /* Determine whether the cache item has existed in the main cache zone */
    if(DNSCache_FindFromCache(Item, BufferItr - Item, NULL, CurrentTime) == NULL)
    {
        /* If not, add it */

        /* Subscript of a chunk in the main cache zone */
        int32_t Subscript;

        uint32_t RecordTTL;

        /* Node with subscript `Subscript' */
        Cht_Node    *Node;

        if( TtlContent != NULL )
        {
            switch( TtlContent->State )
            {
                case TTL_STATE_NO_CACHE:
                    RecordTTL = 0;
                    break;

                case TTL_STATE_ORIGINAL:
                    RecordTTL = i->GetTTL(i);
                    break;

                default:
                    RecordTTL = (TtlContent->Coefficient) * i->GetTTL(i) + (TtlContent->Increment);
                    break;
            }
        } else {
            RecordTTL = i->GetTTL(i);
        }

        if( RecordTTL == 0 )
        {
            return 0;
        }

        /* Get a usable chunk and its subscript */
        Subscript = DNSCache_GetAviliableChunk(BufferItr - Buffer, &Node);

        /* If there is a usable chunk */
        if(Subscript >= 0)
        {
            /* Copy the cache to this entry */
            memcpy(MapStart + Node->Offset, Buffer, BufferItr - Buffer);
            Node->UsedLength = BufferItr - Buffer;

            if( CacheParallel )
            {
                /* Exact match: requires trailing '\x0' */
                RecordTTL = DNSCache_CacheMinTTL(Item, strlen(Item) + 1, RecordTTL, CurrentTime);
            }

            /* Assign TTL */
            Node->TTL = RecordTTL;

            Node->TimeAdded = CurrentTime;

            /* Index this entry on the hash table */
            CacheHT_InsertToSlot(CacheInfo, Item, Subscript, Node, NULL);

            ++(*CacheCount);
        } else {
            return -1;
        }
    }

    return 0;
}

int DNSCache_AddItemsToCache(MsgContext *MsgCtx, BOOL IsFirst)
{
    IHeader *Header = (IHeader *)MsgCtx;
    char *DnsEntity = IHEADER_TAIL(Header);
    const CtrlContent *TtlContent = NULL;

    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    if(Inited == FALSE) return 0;
    if(!IsFirst && !CacheParallel) return 0;

    if( DnsSimpleParser_Init(&p, DnsEntity, Header->EntityLength, FALSE) != 0 )
    {
        return -1;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return -2;
    }

    TtlContent =  CacheTtlCrtl_Get(TtlCtrl, Header->Domain);
    RWLock_WrLock(CacheLock);

    while( i.Next(&i) != NULL )
    {
        BOOL RightPurpose = i.Purpose != DNS_RECORD_PURPOSE_UNKNOWN &&
                            i.Purpose != DNS_RECORD_PURPOSE_QUESTION;

        BOOL CachedType = i.Type == DNS_TYPE_A ||
                          i.Type == DNS_TYPE_AAAA ||
                          i.Type == DNS_TYPE_HTTPS ||
                          i.Type == DNS_TYPE_CNAME;

        BOOL CachedClass = i.Klass == DNS_CLASS_IN;

        if( RightPurpose && CachedType && CachedClass )
        {
            DNSCache_AddAItemToCache(&i, time(NULL), TtlContent);
        }
    }

    RWLock_UnWLock(CacheLock);

    return 0;
}

/* State code returned */
static int DNSCache_GetRawRecordsFromCache(__in    const char *Name,
                                           __in    DNSRecordType Type,
                                           __in    DNSRecordClass Klass,
                                           __inout DnsGenerator *g,
                                           __in    time_t CurrentTime
                                           )
{
    int Ret = -100;

    char Name_Type_Class[253 + 1 + 4 + 1 + 4 + 1];

    uint32_t    NewTTL;

    Cht_Node *Node = NULL; /* Important */

    if( snprintf(Name_Type_Class,
             sizeof(Name_Type_Class),
             "%s\1%X\1%X",
             Name,
             Type,
             Klass
             )
        >= sizeof(Name_Type_Class)
        ) {
            return -609;
    }

    do
    {
        Node = DNSCache_FindFromCache(Name_Type_Class,
                                      strlen(Name_Type_Class) + 1,
                                      Node,
                                      CurrentTime
                                      );

        if( Node == NULL )
        {
            break;
        }

        Ret = 0;

        if( Node->TTL != 0 )
        {
            char *CacheItr;

            /* TTL*/
            if( IgnoreTTL == TRUE )
            {
                NewTTL = Node->TTL;
            } else {
                NewTTL = Node->TTL - (CurrentTime - Node->TimeAdded);
            }

            /* Skip key to get data */
            for(CacheItr = MapStart + Node->Offset + 1;
                *CacheItr != '\0';
                ++CacheItr
            );
            ++CacheItr;

            /* Now the data position */
            switch( Type )
            {
            case DNS_TYPE_CNAME:
                if( g->CName(g, Name, CacheItr, NewTTL) != 0 )
                {
                    return -1;
                }
                break;

            default:
                if( g->RawData(g, Name, Type, Klass, CacheItr,
                               MapStart + Node->Offset + Node->UsedLength - CacheItr,
                               NewTTL) != 0 )
                {
                    return -256;
                }
                break;
            }
        }
    } while ( TRUE );

    return Ret;
}

static Cht_Node *DNSCache_GetCNameFromCache(__in char *Name,
                                            __out char *Buffer,
                                            __in time_t CurrentTime
                                            )
{
    char Name_Type_Class[253 + 1 + 4 + 1 + 4 + 1];
    Cht_Node *Node = NULL;

    if( snprintf(Name_Type_Class,
                 sizeof(Name_Type_Class),
                 "%s\1%X\1%X", Name,
                 DNS_TYPE_CNAME,
                 1) >= sizeof(Name_Type_Class)
                 )
    {
        return NULL;
    }

    do
    {
        Node = DNSCache_FindFromCache(Name_Type_Class,
                                      strlen(Name_Type_Class) + 1,
                                      Node,
                                      CurrentTime
                                      );
        if( Node == NULL )
        {
            return NULL;
        }

        strcpy(Buffer, MapStart + Node->Offset + 1 + strlen(Name_Type_Class) + 1);
        return Node;

    } while( TRUE );

}

/* State code returned */
static int DNSCache_GetByQuestion(__inout DnsGenerator *g,
                                  __inout DnsSimpleParser *p,
                                  __in time_t CurrentTime
                                  )
{
    char    Name[253 + 1];

    DnsSimpleParserIterator i;

    if( DnsSimpleParserIterator_Init(&i, p) != 0 )
    {
        return -1;
    }

    if( i.Next(&i) == NULL || i.Purpose != DNS_RECORD_PURPOSE_QUESTION )
    {
        return -2;
    }

    if( i.Klass != DNS_CLASS_IN ||
        (i.Type != DNS_TYPE_CNAME &&
            i.Type != DNS_TYPE_A &&
            i.Type != DNS_TYPE_AAAA &&
            i.Type != DNS_TYPE_HTTPS
            )
        )
    {
        return -4;
    }

    if( i.GetName(&i, Name, sizeof(Name)) < 0 )
    {
        return -3;
    }

    RWLock_RdLock(CacheLock);

    /* If the intended type is not DNS_TYPE_CNAME, then first find its cname */
    if( i.Type != DNS_TYPE_CNAME )
    {
        char    CName[253 + 1];
        Cht_Node *Node = NULL;

        while( (Node = DNSCache_GetCNameFromCache(Name, CName, CurrentTime))
               != NULL
               )
        {
            uint32_t NewTTL;

            if( IgnoreTTL == TRUE )
            {
                NewTTL = Node->TTL;
            } else {
                NewTTL = Node->TTL - (CurrentTime - Node->TimeAdded);
            }

            if( g->CName(g, "a", CName, NewTTL) != 0 )
            {
                RWLock_UnRLock(CacheLock);
                return -5;
            }

            strcpy(Name, CName);
        }
    }

    if( DNSCache_GetRawRecordsFromCache(Name, i.Type, i.Klass, g, CurrentTime)
        != 0
        )
    {
        RWLock_UnRLock(CacheLock);
        return -6;
    }

    RWLock_UnRLock(CacheLock);
    return 0;
}

/* Content length returned */
int DNSCache_FetchFromCache(MsgContext *MsgCtx, int BufferLength)
{
    IHeader *h = (IHeader *)MsgCtx;
    char *RequestContent = (char *)(h + 1);

    DnsSimpleParser p;
    DnsGenerator g;

    char *HereToGenerate = RequestContent + h->EntityLength;
    int LeftBufferLength = BufferLength - sizeof(IHeader) - h->EntityLength;

    int ResultLength;

    if( Inited != TRUE )
    {
        return -792;
    }

    if( DnsSimpleParser_Init(&p, RequestContent, h->EntityLength, FALSE) != 0 )
    {
        return -1;
    }

    if( DnsGenerator_Init(&g,
                          HereToGenerate,
                          LeftBufferLength,
                          RequestContent,
                          h->EntityLength,
                          TRUE
                          )
       != 0)
    {
        return -2;
    }

    if( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER )
    {
        return -5;
    }

    if( DNSCache_GetByQuestion(&g, &p, time(NULL)) != 0 )
    {
        return -3;
    }

    g.Header->Flags.Direction = 1;
    g.Header->Flags.AuthoritativeAnswer = 0;
    g.Header->Flags.RecursionAvailable = 1;
    g.Header->Flags.ResponseCode = 0;
    g.Header->Flags.Type = 0;

    /* hop-by-hop extension:
        EDNS Extensions: https://datatracker.ietf.org/doc/html/rfc6891
        EDNS0: https://datatracker.ietf.org/doc/html/rfc2671
        DNSSEC Indicating: https://datatracker.ietf.org/doc/html/rfc3225
     */
    if( h->EDNSEnabled )
    {
        while( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ADDITIONAL );
        if( g.EDns(&g, 1280) != 0 )
        {
            return -4;
        }
    }

    ResultLength = DNSCompress(HereToGenerate, g.Length(&g));
    if( ResultLength < 0 )
    {
        return -6;
    }

    memmove(RequestContent, HereToGenerate, ResultLength);

    h->EntityLength = ResultLength;
    if( MsgContext_SendBack(MsgCtx) < 0 )
    {
        /** TODO: Error handling */
        return -861;
    }

    ShowNormalMessage(h, 'C');
    DomainStatistic_Add(h, STATISTIC_TYPE_CACHE);

    return 0;
}
