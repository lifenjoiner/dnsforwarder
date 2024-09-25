#include <string.h>
#include "mmgr.h"
#include "stringchunk.h"
#include "utils.h"
#include "filter.h"
#include "hosts.h"
#include "dnscache.h"
#include "logs.h"
#include "ipmisc.h"
#include "readline.h"
#include "rwlock.h"

typedef int (*SendFunc)(void *Module,
                        IHeader *h, /* Entity followed */
                        int BufferLength
                        );

typedef struct _ModuleInterface {
    union {
        UdpM    Udp;
        TcpM    Tcp;
    } ModuleUnion;

    SendFunc    Send;

    const char *ModuleName;

} ModuleInterface;

typedef struct _ModuleMap {
    StableBuffer *Modules;      /* Storing ModuleInterfaces */
    Array        *ModuleArray;  /* ModuleInterfaces' references */
    StringChunk  *Distributor;  /* Domain-to-ModuleInterface mapping */
} ModuleMap;

static ModuleMap    *CurModuleMap = NULL;
static RWLock       ModulesLock = NULL_RWLOCK;
static ConfigFileInfo *CurrConfigInfo = NULL;

static BOOL EnableUDPtoTCP;
static BOOL EnableTCPtoUDP;

int TCPM_Keep_Alive = 2;

static void DomainList_Tidy(StringList *DomainList)
{
    DomainList->TrimAll(DomainList, "\t .");
    DomainList->LowercaseAll(DomainList);
}

static int MappingAModule(ModuleMap *ModuleMap,
                          ModuleInterface *Stored,
                          StringList *DomainList
                          )
{
    StringListIterator  i;
    const char *OneDomain;

    if( StringListIterator_Init(&i, DomainList) != 0 )
    {
        return -46;
    }

    while( (OneDomain = i.Next(&i)) != NULL )
    {
        StringChunk_Add_Domain(ModuleMap->Distributor,
                               OneDomain,
                               &Stored,
                               sizeof(ModuleInterface *)
                               );
    }

    return 0;
}

static ModuleInterface *StoreAModule(ModuleMap *ModuleMap)
{
    ModuleInterface *Added;

    Added = ModuleMap->Modules->Add(ModuleMap->Modules, NULL, sizeof(ModuleInterface), TRUE);
    if( Added == NULL )
    {
        return NULL;
    }

    if( Array_PushBack(ModuleMap->ModuleArray, &Added, NULL) < 0 )
    {
        return NULL;
    }

    Added->ModuleName = "Unknown";

    return Added;
}

static int Udp_Init_Core(ModuleMap *ModuleMap,
                         const char *Services,
                         StringList *DomainList,
                         const char *Parallel
                         )
{
    ModuleInterface *NewM;

    char ParallelOnOff[8];
    BOOL ParallelQuery;

    if( Services == NULL || DomainList == NULL || Parallel == NULL )
    {
        return -99;
    }

    NewM = StoreAModule(ModuleMap);
    if( NewM == NULL )
    {
        return -101;
    }

    NewM->ModuleName = "UDP";

    strncpy(ParallelOnOff, Parallel, sizeof(ParallelOnOff));
    ParallelOnOff[sizeof(ParallelOnOff) - 1] = '\0';
    StrToLower(ParallelOnOff);

    if( strcmp(ParallelOnOff, "on") == 0 )
    {
        ParallelQuery = TRUE;
    } else {
        ParallelQuery = FALSE;
    }

    /* Initializing module */
    if( UdpM_Init(&(NewM->ModuleUnion.Udp), Services, ParallelQuery) != 0 )
    {
        return -128;
    }

    NewM->Send = (SendFunc)(NewM->ModuleUnion.Udp.Send);

    if( MappingAModule(ModuleMap, NewM, DomainList) != 0 )
    {
        ERRORMSG("Mapping UDP module of %s failed.\n", Services);
    }

    return 0;
}

static int Udp_Init(ModuleMap *ModuleMap, StringListIterator *i)
{
    const char *Services;
    const char *Domains;
    const char *Parallel;

    StringList DomainList;
    int ret = 0;

    /* Initializing parameters */
    Services = i->Next(i);
    Domains = i->Next(i);
    Parallel = i->Next(i);

    if( Domains == NULL )
    {
        return -143;
    }

    if( StringList_Init(&DomainList, Domains, ",") != 0 )
    {
        return -148;
    }

    DomainList_Tidy(&DomainList);

    if( Udp_Init_Core(ModuleMap, Services, &DomainList, Parallel) != 0 )
    {
        ret = -153;
    }

    DomainList.Free(&DomainList);

    return ret;
}

static int Tcp_Init_Core(ModuleMap *ModuleMap,
                         const char *Services,
                         StringList *DomainList,
                         const char *Parallel,
                         const char *Proxies
                         )
{
    ModuleInterface *NewM;

    char OptionString[8];
    BOOL ParallelQuery;

    if( Services == NULL || DomainList == NULL || Parallel == NULL || Proxies == NULL )
    {
        return -157;
    }

    NewM = StoreAModule(ModuleMap);
    if( NewM == NULL )
    {
        return -192;
    }

    NewM->ModuleName = "TCP";

    strncpy(OptionString, Parallel, sizeof(OptionString));
    OptionString[sizeof(OptionString) - 1] = '\0';
    StrToLower(OptionString);

    if( strcmp(OptionString, "on") == 0 )
    {
        ParallelQuery = TRUE;
    } else {
        ParallelQuery = FALSE;
    }

    strncpy(OptionString, Proxies, sizeof(OptionString));
    OptionString[sizeof(OptionString) - 1] = '\0';
    StrToLower(OptionString);

    if( strcmp(OptionString, "no") == 0 )
    {
        Proxies = NULL;
    }

    /* Initializing module */
    if( TcpM_Init(&(NewM->ModuleUnion.Tcp), Services, ParallelQuery, Proxies) != 0 )
    {
        return -180;
    }

    NewM->Send = (SendFunc)(NewM->ModuleUnion.Tcp.Send);

    if( MappingAModule(ModuleMap, NewM, DomainList) != 0 )
    {
        ERRORMSG("Mapping TCP module of %s failed.\n", Services);
    }

    return 0;
}

static int Tcp_Init(ModuleMap *ModuleMap, StringListIterator *i)
{
    const char *Services;
    const char *Domains;
    const char *Parallel;
    const char *Proxies;

    StringList DomainList;
    int ret = 0;

    /* Initializing parameters */
    Services = i->Next(i);
    Domains = i->Next(i);
    Parallel = i->Next(i);
    Proxies = i->Next(i);

    if( Domains == NULL )
    {
        return -143;
    }

    if( StringList_Init(&DomainList, Domains, ",") != 0 )
    {
        return -148;
    }

    DomainList_Tidy(&DomainList);

    if( Tcp_Init_Core(ModuleMap, Services, &DomainList, Parallel, Proxies) != 0 )
    {
        ret = -233;
    }

    DomainList.Free(&DomainList);

    return ret;
}

/*
# UDP
PROTOCOL UDP
SERVER 1.2.4.8,127.0.0.1
PARALLEL ON

LIST domainlist.txt

example.com

#############################
# TCP
PROTOCOL TCP
SERVER 1.2.4.8,127.0.0.1
PARALLEL ON
PROXY NO

LIST domainlist.txt

example.com

#############################
# TCP
PROTOCOL TCP
SERVER 1.2.4.8,127.0.0.1
PARALLEL OFF
PROXY 192.168.1.1:8080,192.168.1.1:8081

example.com

*/
static int Modules_InitFromFile(ModuleMap *ModuleMap, StringListIterator *i)
{
    #define MAX_PATH_BUFFER     384

    StringChunk Args;
    StringList  Domains;

    const char *FileOri;
    char File[MAX_PATH_BUFFER];
    FILE *fp;

    ReadLineStatus  Status;

    const char *Protocol = NULL;
    const char *List = NULL;

    int ret = 0;

    FileOri = i->Next(i);

    if( FileOri == NULL )
    {
        return -201;
    }

    if( ExpandPathTo(File, MAX_PATH_BUFFER, FileOri) != 0 )
    {
        ERRORMSG("Failed to expand path: %s.\n", FileOri);
        return -202;
    }

    fp = fopen(File, "r");
    if( fp == NULL )
    {
        WARNING("Cannot open group file \"%s\".\n", File);
        return 0;
    }

    if( StringChunk_Init(&Args, NULL) != 0 )
    {
        fclose(fp);
        return -230;
    }

    if( StringList_Init(&Domains, NULL, NULL) != 0 )
    {
        fclose(fp);
        ret = -235;
        goto EXIT_1;
    }

    do {
        char Buffer[MAX_PATH_BUFFER];
        const char *Value;

        Status = ReadLine(fp, Buffer, sizeof(Buffer));

        if( Status == READ_TRUNCATED )
        {
            WARNING("Line is too long %s, file \"%s\".\n", Buffer, File);
            ReadLine_GoToNextLine(fp);
            continue;
        }

        if( Status == READ_FAILED_OR_END )
        {
            break;
        }

        StrToLower(Buffer);

        Value = SplitNameAndValue(Buffer, " \t=");
        if( Value != NULL )
        {
            StringChunk_Add(&Args, Buffer, Value, strlen(Value) + 1);
        } else {
            Domains.Add(&Domains, Buffer, NULL);
        }

    } while( TRUE );

    fclose(fp);

    if( !StringChunk_Match_NoWildCard(&Args,
                                      "protocol",
                                      NULL,
                                      (void **)&Protocol,
                                      NULL,
                                      NULL
                                      ) ||
        Protocol == NULL
        )
    {
        ERRORMSG("No protocol specified, file \"%s\".\n", File);
        ret = -270;
        goto EXIT_2;
    }

    if( StringChunk_Match_NoWildCard(&Args, "list", NULL, (void **)&List, NULL, NULL) && List != NULL )
    {
        char ListFile[MAX_PATH_BUFFER];

        if( ExpandPathTo(ListFile, MAX_PATH_BUFFER, List) != 0 )
        {
            ERRORMSG("Failed to expand path: %s.\n", List);
            ret = -202;
            goto EXIT_2;
        }

        fp = fopen(ListFile, "r");
        if( fp == NULL )
        {
            WARNING("Cannot open group domain list file \"%s\".\n", ListFile);
        } else {
            do {
                char Buffer[MAX_PATH_BUFFER];

                Status = ReadLine(fp, Buffer, sizeof(Buffer));

                if( Status == READ_TRUNCATED )
                {
                    WARNING("Line is too long %s, file \"%s\".\n", Buffer, ListFile);
                    ReadLine_GoToNextLine(fp);
                    continue;
                }

                if( Status == READ_FAILED_OR_END )
                {
                    break;
                }

                StrToLower(Buffer);

                Domains.Add(&Domains, Buffer, NULL);
            } while( TRUE );

            fclose(fp);
        }
    }

    DomainList_Tidy(&Domains);

    if( Domains.Count(&Domains) == 0 )
    {
        ret = 0;
        goto EXIT_2;
    }

    if( strcmp(Protocol, "udp") == 0 )
    {
        const char *Services = NULL;
        const char *Parallel = "on";

        StringChunk_Match_NoWildCard(&Args, "server", NULL, (void **)&Services, NULL, NULL);
        StringChunk_Match_NoWildCard(&Args, "parallel", NULL, (void **)&Parallel, NULL, NULL);

        if( Udp_Init_Core(ModuleMap, Services, &Domains, Parallel) != 0 )
        {
            ERRORMSG("Loading group file \"%s\" failed.\n", File);
            ret = -337;
        }

    } else if( strcmp(Protocol, "tcp") == 0 )
    {
        const char *Services = NULL;
        const char *Parallel = "on";
        const char *Proxies = "no";

        StringChunk_Match_NoWildCard(&Args, "server", NULL, (void **)&Services, NULL, NULL);
        StringChunk_Match_NoWildCard(&Args, "parallel", NULL, (void **)&Parallel, NULL, NULL);
        StringChunk_Match_NoWildCard(&Args, "proxy", NULL, (void **)&Proxies, NULL, NULL);

        if( Tcp_Init_Core(ModuleMap, Services, &Domains, Parallel, Proxies) != 0 )
        {
            ERRORMSG("Loading group file \"%s\" failed.\n", File);
            ret = -233;
        }

    } else {
        ERRORMSG("Unknown protocol %s, file \"%s\".\n", Protocol, File);
        ret = -281;
    }

EXIT_2:
    Domains.Free(&Domains);
EXIT_1:
    StringChunk_Free(&Args, TRUE);

    return ret;
}

static int Modules_Init(ModuleMap *ModuleMap, ConfigFileInfo *ConfigInfo)
{
    StringList  *ServerGroups;
    StringListIterator  i;

    const char *Type;

    ServerGroups = ConfigGetStringList(ConfigInfo, "ServerGroup");
    if( ServerGroups == NULL )
    {
        ERRORMSG("Please set at least one server group.\n");
        return -202;
    }

    if( StringListIterator_Init(&i, ServerGroups) != 0 )
    {
        return -207;
    }

    while( (Type = i.Next(&i)) != NULL )
    {
        if( strcmp(Type, "UDP") == 0 )
        {
            if( Udp_Init(ModuleMap, &i) != 0 )
            {
                ERRORMSG("Initializing UDPGroups failed.\n");
                return -218;
            }
        } else if( strcmp(Type, "TCP") == 0 )
        {
            if( Tcp_Init(ModuleMap, &i) != 0 )
            {
                ERRORMSG("Initializing TCPGroups failed.\n");
                return -226;
            }
        } else if( strcmp(Type, "FILE") == 0 )
        {
            if( Modules_InitFromFile(ModuleMap, &i) != 0 )
            {
                ERRORMSG("Initializing group files failed.\n");
                return -318;
            }
        } else {
            ERRORMSG("Initializing server groups failed, near %s.\n", Type);
            return -230;
        }
    }

    INFO("Loading Server Groups completed.\n", Type);
    return 0;
}

static void Modules_Free(ModuleMap *ModuleMap)
{
    if( ModuleMap == NULL )
    {
        return;
    }
    if( ModuleMap->Modules != NULL )
    {
        ModuleMap->Modules->Free(ModuleMap->Modules);
        SafeFree(ModuleMap->Modules);
    }
    if( ModuleMap->ModuleArray != NULL )
    {
        Array_Free(ModuleMap->ModuleArray);
        SafeFree(ModuleMap->ModuleArray);
    }
    if( ModuleMap->Distributor != NULL )
    {
        StringChunk_Free(ModuleMap->Distributor, TRUE);
        SafeFree(ModuleMap->Distributor);
    }
    SafeFree(ModuleMap);
}

static int
#ifdef WIN32
WINAPI
#endif
Modules_SafeCleanup(ModuleMap *ModuleMap)
{
    StableBufferIterator BI;
    ModuleInterface *M = NULL;
    int i, BytesOfMetaInfo;
    BOOL InUse = TRUE;

    if( ModuleMap == NULL  || StableBufferIterator_Init(&BI, ModuleMap->Modules) != 0 )
    {
        return -1;
    }

    while( InUse )
    {
        InUse = FALSE;
        BI.Reset(&BI);
        while( (M = BI.NextBlock(&BI)) != NULL )
        {
            BytesOfMetaInfo = BI.CurrentBlockUsed(&BI);
            for( i = 0; i * sizeof(ModuleInterface) < BytesOfMetaInfo; ++i, ++M )
            {
                if( strcmp(M->ModuleName, "UDP") == 0 )
                {
                    M->ModuleUnion.Udp.IsServer = 0;
                    InUse |= M->ModuleUnion.Udp.WorkThread != NULL_THREAD;
                    InUse |= M->ModuleUnion.Udp.SwepThread != NULL_THREAD;
                }
                else if( strcmp(M->ModuleName, "TCP") == 0 )
                {
                    M->ModuleUnion.Tcp.IsServer = 0;
                    InUse |= M->ModuleUnion.Tcp.WorkThread != NULL_THREAD;
                }
            }
        }

        if( !InUse )
        {
            break;
        }

        SLEEP(1000);
    }

    Modules_Free(ModuleMap);
    INFO("Last GroupFile Modules freed.\n");

    return 0;
}

static int Modules_Load(ConfigFileInfo *ConfigInfo)
{
    ModuleMap *NewModuleMap;
    ThreadHandle th;
    int ret;

    CurrConfigInfo = ConfigInfo;

    NewModuleMap = SafeMalloc(sizeof(ModuleMap));
    if( NewModuleMap == NULL )
    {
        return -1;
    }

    NewModuleMap->Distributor = NULL;
    if( InitChunk(&(NewModuleMap->Distributor)) != 0 )
    {
        ret = -10;
        goto ModulesFree;
    }

    NewModuleMap->Modules = SafeMalloc(sizeof(StableBuffer));
    if( NewModuleMap->Modules == NULL)
    {
        ret = -27;
        goto ModulesFree;
    }

    if( StableBuffer_Init(NewModuleMap->Modules) != 0 )
    {
        ret = -27;
        goto ModulesFree;
    }

    NewModuleMap->ModuleArray = SafeMalloc(sizeof(Array));
    if( NewModuleMap->ModuleArray == NULL)
    {
        ret = -98;
        goto ModulesFree;
    }

    if( Array_Init(NewModuleMap->ModuleArray,
                   sizeof(ModuleInterface *),
                   0,
                   FALSE,
                   NULL
                   )
       != 0 )
    {
        ret = -98;
        goto ModulesFree;
    }

    ret = Modules_Init(NewModuleMap, ConfigInfo);

    if (ret)
    {
        goto ModulesFree;
    }

    RWLock_WrLock(ModulesLock);

    CREATE_THREAD(Modules_SafeCleanup, CurModuleMap, th);
    DETACH_THREAD(th);
    CurModuleMap = NewModuleMap;

    RWLock_UnWLock(ModulesLock);

    INFO("Loading GroupFile(s) completed.\n");

    return 0;

ModulesFree:
    Modules_Free(NewModuleMap);
    INFO("Loading GroupFile(s) failed.\n");
    return ret;
}

static void Modules_Cleanup(void)
{
    if( CurModuleMap != NULL )
    {
        Modules_Free(CurModuleMap);
    }
    RWLock_Destroy(ModulesLock);
}

int MMgr_Init(ConfigFileInfo *ConfigInfo)
{
    int ret;

    EnableUDPtoTCP = ConfigGetBoolean(ConfigInfo, "EnableUDPtoTCP");
    EnableTCPtoUDP = ConfigGetBoolean(ConfigInfo, "EnableTCPtoUDP");
    TCPM_Keep_Alive = ConfigGetInt32(ConfigInfo, "TCPKeepAlive");

    RWLock_Init(ModulesLock);

    ret = Modules_Load(ConfigInfo);
    if( ret != 0 )
    {
        return ret;
    }
    atexit(Modules_Cleanup);

    if( Filter_Init(ConfigInfo) != 0 )
    {
        return -159;
    }

    if( DNSCache_Init(ConfigInfo) != 0 )
    {
        return -164;
    }

    if( IpMiscMapping_Init(ConfigInfo) != 0 )
    {
        return -176;
    }

    /* The last: reloading */
    if( Hosts_Init(ConfigInfo) != 0 )
    {
        return -165;
    }

    INFO("Loading Configuration completed.\n");

    return 0;
}

int Modules_Update(void)
{
    if ( ConfigGetBoolean(CurrConfigInfo, "ReloadGroupFile") )
    {
        Modules_Load(CurrConfigInfo);
    }
    return 0;
}

static BOOL ModuleFitRequest(const void **Data, const void *Expected)
{
    const ModuleInterface *m = *(ModuleInterface **)Data;
    const MsgContext *MsgCtx = (MsgContext *)Expected;

    if( MsgContext_IsFromTCP(MsgCtx) || ((IHeader *)Expected)->RequestTcp )
    {
        if( EnableTCPtoUDP == FALSE )
        {
            if( strcmp(m->ModuleName, "UDP") == 0 )
            {
                return FALSE;
            }
        }
    } else if( EnableUDPtoTCP == FALSE ) {
        if( strcmp(m->ModuleName, "TCP") == 0 )
        {
            return FALSE;
        }
    }

    return TRUE;
}

int MMgr_Send(const char *Buffer, int BufferLength)
{
    ModuleInterface **i;
    ModuleInterface *TheModule;
    MsgContext *MsgCtx = (MsgContext *)Buffer;
    IHeader *h = (IHeader *)Buffer;

    int ret;

    /* Determine whether to discard the query */
    if( Filter_Out(MsgCtx) )
    {
        return 0;
    }

    /* Hosts & Cache */
    if( Hosts_Get(MsgCtx, BufferLength) == 0 )
    {
        return 0;
    }

    if( DNSCache_FetchFromCache(MsgCtx, BufferLength) == 0 )
    {
        return 0;
    }

    /* Ordinary models */

    RWLock_RdLock(ModulesLock);

    if( StringChunk_Domain_Match_WildCardRandom(CurModuleMap->Distributor,
                                                 h->Domain,
                                                 &(h->HashValue),
                                                 (void **)&i,
                                                 ModuleFitRequest,
                                                 h
                                                 )
       )
    {
    } else if( Array_GetUsed(CurModuleMap->ModuleArray) > 0 ){
        i = Array_GetBySubscript(CurModuleMap->ModuleArray,
                                 (int)(DNSGetQueryIdentifier(IHEADER_TAIL(h))) %
                                 Array_GetUsed(CurModuleMap->ModuleArray)
                                 );
    } else {
        i = NULL;
    }

    if( i == NULL || *i == NULL )
    {
        ret = -190;
    } else {
        TheModule = *i;
        ret = TheModule->Send(&(TheModule->ModuleUnion), h, BufferLength);
    }

    RWLock_UnRLock(ModulesLock);

    return ret;
}
