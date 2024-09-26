#include "hosts.h"
#include "addresslist.h"
#include "mcontext.h"
#include "socketpuller.h"
#include "goodiplist.h"
#include "logs.h"
#include "domainstatistic.h"
#include "mmgr.h"

extern BOOL Ipv6_Enabled;

static BOOL BlockIpv6WhenIpv4Exists = FALSE;

static SOCKET   InnerSocket;
static Address_Type InnerAddress;
static SocketPuller Puller;

BOOL Hosts_TypeExisting(const char *Domain, HostsRecordType Type)
{
    return StaticHosts_TypeExisting(Domain, Type) ||
           DynamicHosts_TypeExisting(Domain, Type);
}

static HostsUtilsTryResult Hosts_Try_Inner(MsgContext *MsgCtx, int BufferLength)
{
    HostsUtilsTryResult ret;

    ret = StaticHosts_Try(MsgCtx, BufferLength);
    if( ret != HOSTSUTILS_TRY_NONE )
    {
        return ret;
    }

    return DynamicHosts_Try(MsgCtx, BufferLength);
}

static int Hosts_GetCName(const char *Domain, char *Buffer)
{
    return !(StaticHosts_GetCName(Domain, Buffer) == 0 ||
           DynamicHosts_GetCName(Domain, Buffer) == 0);
}

HostsUtilsTryResult Hosts_Try(MsgContext *MsgCtx, int BufferLength)
{
    HostsUtilsTryResult ret;
    IHeader *Header = (IHeader *)MsgCtx;

    if( BlockIpv6WhenIpv4Exists )
    {
        if( Header->Type == DNS_TYPE_AAAA &&
            (Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_A) ||
             Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_GOOD_IP_LIST)
             )
            )
        {
            /** TODO: Show blocked message */
            return HOSTSUTILS_TRY_BLOCKED;
        }
    }

    if( Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_EXCLUEDE) )
    {
        return HOSTSUTILS_TRY_NONE;
    }

    ret = Hosts_Try_Inner(MsgCtx, BufferLength);

    if( ret == HOSTSUTILS_TRY_RECURSED )
    {
        if( sendto(InnerSocket,
                   (const char *)Header, /* Only send header and identifier */
                   sizeof(IHeader) + sizeof(uint16_t), /* Only send header and identifier */
                   MSG_NOSIGNAL,
                   (const struct sockaddr *)&(InnerAddress.Addr),
                   GetAddressLength(InnerAddress.family)
                   )
            < 0 )
        {
            return HOSTSUTILS_TRY_NONE;
        }
    }

    return ret;
}

int Hosts_Get(MsgContext *MsgCtx, int BufferLength)
{
    IHeader *Header = (IHeader *)MsgCtx;

    switch( Hosts_Try(MsgCtx, BufferLength) )
    {
    case HOSTSUTILS_TRY_BLOCKED:
        MsgContext_SendBackRefusedMessage(MsgCtx);
        ShowRefusingMessage(Header, "Disabled because of existing IPv4 host");
        DomainStatistic_Add(Header, STATISTIC_TYPE_REFUSED);
        return 0;
        break;

    case HOSTSUTILS_TRY_NONE:
        return -126;
        break;

    case HOSTSUTILS_TRY_RECURSED:
        /** TODO: Show hosts message */
        return 0;

    case HOSTSUTILS_TRY_OK:
        ShowNormalMessage(Header, 'H');
        DomainStatistic_Add(Header, STATISTIC_TYPE_HOSTS);
        return 0;
        break;

    default:
        return -139;
        break;
    }
}

static int
#ifdef WIN32
WINAPI
#endif
Hosts_SocketLoop(void *Unused)
{
    ModuleContext Context;

    SOCKET   OuterSocket;
    Address_Type OuterAddress;

    const struct timeval LongTime = {3600, 0};
    const struct timeval ShortTime = {10, 0};

    struct timeval  TimeLimit = LongTime;

    #define LEFT_LENGTH_SL (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))

    char    InnerBuffer[SOCKET_CONTEXT_LENGTH];
    MsgContext *InnerMsgCtx = (MsgContext *)InnerBuffer;
    IHeader *InnerHeader = (IHeader *)InnerBuffer;
    /* char    *InnerEntity = InnerBuffer + sizeof(IHeader); */

    char OuterBuffer[SOCKET_CONTEXT_LENGTH];
    /* MsgContext *OuterMsgCtx = (MsgContext *)OuterBuffer; */
    IHeader *OuterHeader = (IHeader *)OuterBuffer;
    char    *OuterEntity = OuterBuffer + sizeof(IHeader);

    int State;
    int ret = 0;

    OuterSocket = TryBindLocal(Ipv6_Enabled, 10300, &OuterAddress);

    if( OuterSocket == INVALID_SOCKET )
    {
        return -416;
    }

    if( SocketPuller_Init(&Puller, 0) != 0 )
    {
        ret = -423;
        goto EXIT_1;
    }

    Puller.Add(&Puller, InnerSocket, NULL, 0);
    Puller.Add(&Puller, OuterSocket, NULL, 0);

    if( ModuleContext_Init(&Context, SOCKET_CONTEXT_LENGTH) != 0 )
    {
        ret = -431;
        goto EXIT_1;
    }

    srand(time(NULL));

    while( TRUE )
    {
        SOCKET  Pulled;
        int Err;

        Pulled = Puller.Select(&Puller, &TimeLimit, NULL, TRUE, FALSE, &Err);
        if( Pulled == INVALID_SOCKET )
        {
            if( Err != 0 )
            {
                ERRORMSG("Fatal error 70.\n");
                break;
            }
            TimeLimit = LongTime;
            Context.Swep(&Context, NULL, NULL);
        } else if( Pulled == InnerSocket )
        {
            /* Recursive query */
            MsgContext *MsgCtxStored;
            char RecursedDomain[DOMAIN_NAME_LENGTH_MAX + 1];
            uint16_t NewIdentifier;

            TimeLimit = ShortTime;

            State = recvfrom(InnerSocket,
                             InnerBuffer, /* Receiving a header */
                             sizeof(InnerBuffer),
                             0,
                             NULL,
                             NULL
                             );

            if( State < 1 )
            {
                continue;
            }

            if( Hosts_GetCName(InnerHeader->Domain, RecursedDomain) != 0 )
            {
                ERRORMSG("Fatal error 221.\n");
                continue;
            }

            NewIdentifier = rand();

            if( HostsUtils_GenerateQuery(OuterBuffer,
                                         SOCKET_CONTEXT_LENGTH,
                                         OuterSocket,
                                         &OuterAddress,
                                         MsgContext_IsFromTCP(InnerMsgCtx),
                                         NewIdentifier,
                                         RecursedDomain,
                                         InnerHeader->Type
                                         )
                != 0 )
            {
                /** TODO: Show an error */
                continue;
            }

            MsgCtxStored = Context.Add(&Context, InnerMsgCtx);
            if( MsgCtxStored == NULL )
            {
                ERRORMSG("Fatal error 230.\n");
                continue;
            }

            OuterHeader->Parent = (IHeader *)MsgCtxStored;

            MMgr_Send(OuterBuffer, SOCKET_CONTEXT_LENGTH);

        } else if( Pulled == OuterSocket )
        {
            MsgContext *BackTraceMsgCtx;
            IHeader *BackTraceHeader;

            TimeLimit = ShortTime;

            State = recvfrom(OuterSocket,
                             OuterBuffer, /* Receiving a header */
                             sizeof(OuterBuffer),
                             0,
                             NULL,
                             NULL
                             );

            if( State < 1 )
            {
                continue;
            }

            BackTraceHeader = OuterHeader->Parent;
            BackTraceMsgCtx = (MsgContext *)BackTraceHeader;
            DNSCopyQueryIdentifier(InnerHeader + 1, BackTraceHeader + 1);
            if( Context.GenAnswerHeaderAndRemove(&Context, BackTraceMsgCtx, InnerMsgCtx) != 0 )
            {
                ERRORMSG("Fatal error 267.\n");
                continue;
            }

            if( HostsUtils_CombineRecursedResponse((MsgContext *)InnerBuffer,
                                                   SOCKET_CONTEXT_LENGTH,
                                                   OuterEntity,
                                                   State,
                                                   OuterHeader->Domain
                                                   )
                != 0 )
            {
                ERRORMSG("Fatal error 279.\n");
                continue;
            }

            if( MsgContext_SendBack((MsgContext *)InnerBuffer) != 0 )
            {
                ERRORMSG("Fatal error 285.\n");
                continue;
            }

            ShowNormalMessage(InnerHeader, 'H');
        }
    }

    ModuleContext_Free(&Context);

EXIT_1:
    Puller.Free(&Puller);

    return ret;
}

int Hosts_Init(ConfigFileInfo *ConfigInfo)
{
    ThreadHandle t;

    StaticHosts_Init(ConfigInfo);
    DynamicHosts_Init(ConfigInfo);

    GoodIpList_Init(ConfigInfo);

    BlockIpv6WhenIpv4Exists = ConfigGetBoolean(ConfigInfo,
                                                 "BlockIpv6WhenIpv4Exists"
                                                 );

    InnerSocket = TryBindLocal(Ipv6_Enabled, 10200, &InnerAddress);
    if( InnerSocket == INVALID_SOCKET )
    {
        return -25;
    }

    CREATE_THREAD(Hosts_SocketLoop, NULL, t);
    DETACH_THREAD(t);

    return 0;
}
