#include <string.h>
#include "tcpm.h"
#include "stringlist.h"
#include "socketpuller.h"
#include "utils.h"
#include "logs.h"
#include "udpfrontend.h"
#include "timedtask.h"
#include "dnscache.h"
#include "dnsgenerator.h"
#include "ipmisc.h"
#include "domainstatistic.h"
#include "ptimer.h"

extern BOOL Ipv6_Enabled;

#define TIMEOUT     5
#define TIMEOUT_ms_SEND 2000
#define TIMEOUT_ms_RECV 2000
#define TIMEOUT_ms_ALIVE    100

extern int TCPM_Keep_Alive;
static const struct timeval TimeOut_Const = {TIMEOUT, 0};

typedef struct _TcpContext
{
    int     ServerIndex;
    time_t  LastActivity;
    /* To retry for server that force closed SOCKET. */
    int         Queried;
    int         MsgCtxQid;
    uint32_t    MsgCtxHash;
    MsgContext  *MsgCtx;
} TcpContext;

static void SweepWorks(MsgContext *MsgCtx, int Number, TcpM *Module)
{
    IHeader *h = (IHeader *)MsgCtx;

    ShowTimeOutMessage(h, 'T');
    DomainStatistic_Add(h, STATISTIC_TYPE_REFUSED);

    if( Number == 1 && Module->SocksProxies == NULL )
    {
        AddressList_Advance(&(Module->ServiceList));
    }
}

static void TcpM_Connect_Recycle(SocketPuller *Puller, SocketPuller **Backups)
{
    SocketPuller *p;
    TcpContext *TcpCtx;
    int Err;

    while( Puller != NULL )
    {
        SOCKET s = INVALID_SOCKET;
        struct timeval TimeOut = {0, TIMEOUT_ms_ALIVE * 1000};

        s = Puller->Select(Puller, &TimeOut, (void **)&TcpCtx, FALSE, TRUE, &Err);

        if( s == INVALID_SOCKET )
        {
            if( Err != 0 && !ErrorOfVoidSelect(Err) )
            {
                ERRORMSG("TCP fatal error %d.\n", Err);
            }
            break;
        } else {
            Puller->Del(Puller, s);
            DEBUG("Recycled socket for Pullers[%d]\n", TcpCtx->ServerIndex);
            p = Backups[TcpCtx->ServerIndex];
            p->Add(p, s, TcpCtx, sizeof(TcpContext));
        }
    }
}

/* Connection Handling: https://www.rfc-editor.org/rfc/rfc7766#section-6
    To get a clear state of the TCP, we don't use pipeline.
    We use a short keep-alive to avoid the server is non-readable but writable.
*/
static SOCKET TcpM_Connect_GetAvailable(SocketPuller *p, TcpContext **TcpCtx)
{
    SOCKET s = INVALID_SOCKET;
    int Err;


    while( TRUE )
    {
        struct timeval TimeOut = {0, TIMEOUT_ms_ALIVE * 1000};

        s = p->Select(p, &TimeOut, (void **)TcpCtx, FALSE, TRUE, &Err);
        if( s == INVALID_SOCKET )
        {
            if( Err != 0 && !ErrorOfVoidSelect(Err) )
            {
                ERRORMSG("TCP fatal error %d.\n", Err);
            }
            break;
        } else {
            p->Del(p, s); /* Single thread: delete before adding is safe. */

            if( time(NULL) - (*TcpCtx)->LastActivity > TCPM_Keep_Alive ) {
                INFO("Existing TCP connection expired, discard.\n");
                CLOSE_SOCKET(s);
            } else {
                break;
            }
        }
    }

    return s;
}

static SOCKET TcpM_Connect_Addr(sa_family_t af, const struct sockaddr *addr)
{
    SOCKET s = socket(af, SOCK_STREAM, IPPROTO_TCP);

    if( s == INVALID_SOCKET )
    {
        return INVALID_SOCKET;
    }

    if( SetSocketNonBlock(s, TRUE) != 0 )
    {
        CLOSE_SOCKET(s);
        return INVALID_SOCKET;
    }

#if defined(_WIN32) && defined(IPV6_V6ONLY)
    if( af == AF_INET6 )
    {
        SetSocketIPv6V6only(s, 0);
    }
#endif

    if( connect(s, addr, GetAddressLength(af)) != 0 )
    {
        if( GET_LAST_ERROR() != CONNECT_FUNCTION_BLOCKED )
        {
            CLOSE_SOCKET(s);
            return INVALID_SOCKET;
        }
    }

    return s;
}

static int TcpM_Connect(TcpM *m, int ServerIndex, BOOL IsProxy)
{
    struct sockaddr **ServerAddresses;
    sa_family_t *Families;
    const char *Name, *Type;

    SocketPuller **Pullers, *Puller;
    int i, NumOfServers, Shift, idx, n = 0;
    TcpContext *TcpCtx, TcpCtxNew;

    if( m->SocksProxies == NULL || IsProxy == FALSE )
    {
        ServerAddresses = m->Services;
        Families = m->ServiceFamilies;
        Pullers = m->Agents;
        Puller = &(m->QueryPuller);
        Name = m->ServiceName;
        Type = "server";
        NumOfServers = AddressList_GetNumberOfAddresses(&(m->ServiceList));
    } else {
        ServerAddresses = m->SocksProxies;
        Families = m->SocksProxyFamilies;
        Pullers = m->Proxies;
        Puller = &(m->ProxyPuller);
        Name = m->ProxyName;
        Type = "proxy";
        NumOfServers = AddressList_GetNumberOfAddresses(&(m->SocksProxyList));
    }

    TcpM_Connect_Recycle(Puller, Pullers);

    srand(time(NULL));
    Shift = rand();

    idx = ServerIndex;

    if( ServerIndex >= 0 )
    {
        NumOfServers = 1;
    }

    DEBUG("Connecting to %s: %s ...\n", Type, Name);

    for( i = 0; i < NumOfServers; ++i )
    {
        SOCKET s = INVALID_SOCKET;

        if( ServerIndex < 0 )
        {
            idx = (Shift + i) % NumOfServers;
        }

        DEBUG("Pullers[%d]:\n", idx);

        /* Existing */
        s = TcpM_Connect_GetAvailable(Pullers[idx], &TcpCtx);
        if( s != INVALID_SOCKET )
        {
            DEBUG("Got existing connection from Pullers[%d].\n", idx);
            Puller->Add(Puller, s, TcpCtx, sizeof(TcpContext));
            n++;
            continue;
        }

        /* New */
        if( m->SocksProxies == NULL || IsProxy == TRUE )
        {
            s = TcpM_Connect_Addr(Families[idx], ServerAddresses[idx]);
            if( s == INVALID_SOCKET )
            {
                continue;
            }
            DEBUG("Created new connection for Pullers[%d].\n", idx);
            TcpCtxNew.ServerIndex = idx;
            TcpCtxNew.LastActivity = time(NULL);
            TcpCtxNew.Queried = 0;
            TcpCtx = &TcpCtxNew;
        } else {
            if( TcpM_Connect(m, -1, TRUE) > 0 ) {
                s = TcpM_Connect_GetAvailable(&(m->ProxyPuller), &TcpCtx);
                if( s == INVALID_SOCKET )
                {
                    continue;
                }
                DEBUG("Got proxy connection for Pullers[%d].\n", idx);
                TcpCtx->ServerIndex = idx;
            } else {
                continue;
            }
        }

        Puller->Add(Puller, s, TcpCtx, sizeof(TcpContext));
        n++;
    }

    return n;
}

static int TcpM_SendWrapper(SOCKET Sock, const char *Start, int Length)
{
    time_t t = time(NULL);

    while( send(Sock, Start, Length, MSG_NOSIGNAL) != Length )
    {
        int LastError = GET_LAST_ERROR();
        if( FatalErrorDecideding(LastError) != 0 ||
                !SocketIsWritable(Sock, TIMEOUT_ms_SEND) ||
                time(NULL) - t > TIMEOUT_ms_SEND / 1000
                )
        {
            ShowSocketError("Sending to TCP server or proxy failed.", LastError);
            return (-1) * LastError;
        }
    }

    return Length;
}

static int TcpM_RecvWrapper(SOCKET Sock, char *Buffer, int BufferSize)
{
    int Recvlength;
    time_t t = time(NULL);

    while( (Recvlength = recv(Sock, Buffer, BufferSize, 0)) < 0 )
    {
        int LastError = GET_LAST_ERROR();
        if( FatalErrorDecideding(LastError) != 0 ||
                !SocketIsStillReadable(Sock, TIMEOUT_ms_RECV) ||
                time(NULL) - t > TIMEOUT_ms_RECV / 1000
                )
        {
            ShowSocketError("Receiving from TCP server or proxy failed", LastError);
            return (-1) * LastError;
        }
    }
    return Recvlength;
}

static int TcpM_ProxyPreparation(SOCKET Sock,
                                 const struct sockaddr  *NestedAddress,
                                 sa_family_t Family
                                 )
{
    char AddressInfos[4 + 1 + LENGTH_OF_IPV6_ADDRESS_ASCII + 2 + 1];
    char *AddressString = AddressInfos + 5;
    char NumberOfCharacter;
    unsigned short Port;
    char RecvBuffer[16];

    DEBUG("Negotiating with TCP proxy ...\n");

    if( TcpM_SendWrapper(Sock, "\x05\x01\x00", 3) != 3 )
    {
        ERRORMSG("Cannot negotiate with TCP proxy.\n");
        return -1;
    }

    if( TcpM_RecvWrapper(Sock, RecvBuffer, 2) != 2 )
    {
        ERRORMSG("Cannot negotiate with TCP proxy.\n");
        return -2;
    }

    if( RecvBuffer[0] != '\x05' || RecvBuffer[1] != '\x00' )
    {
        ERRORMSG("Cannot negotiate with TCP proxy.\n");
        return -3;
    }

    memcpy(AddressInfos, "\x05\x01\x00\x03", 4);

    if( Family == AF_INET )
    {
        IPv4AddressToAsc(&(((const struct sockaddr_in *)NestedAddress)->sin_addr), AddressString);
        Port = ((const struct sockaddr_in *)NestedAddress)->sin_port;
    } else {
        IPv6AddressToAsc(&(((const struct sockaddr_in6 *)NestedAddress)->sin6_addr), AddressString);
        Port = ((const struct sockaddr_in6 *)NestedAddress)->sin6_port;
    }

    NumberOfCharacter = strlen(AddressString);
    memcpy(AddressInfos + 4, &NumberOfCharacter, 1);
    memcpy(AddressInfos + 5 + NumberOfCharacter,
           (const char *)&Port,
           sizeof(Port)
           );

    DEBUG("Proxy is Connecting to TCP server ...\n");

    if( TcpM_SendWrapper(Sock,
                         AddressInfos,
                         4 + 1 + NumberOfCharacter + 2
                         )
     != 4 + 1 + NumberOfCharacter + 2 )
    {
        ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
        return -4;
    }

    if( TcpM_RecvWrapper(Sock, RecvBuffer, 4) != 4 )
    {
        ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
        return -9;
    }

    if( RecvBuffer[1] != '\x00' )
    {
        ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
        return -10;
    }

    switch( RecvBuffer[3] )
    {
        case 0x01:
            NumberOfCharacter = 6;
            break;

        case 0x03:
            TcpM_RecvWrapper(Sock, &NumberOfCharacter, 1);
            NumberOfCharacter += 2;
            break;

        case 0x04:
            NumberOfCharacter = 18;
            break;

        default:
            ERRORMSG("Proxy Cannot communicate with TCP proxy.\n");
            return -11;
    }
    ClearTCPSocketBuffer(Sock, NumberOfCharacter);

    INFO("Proxy has Connected to TCP server.\n");

    return 0;

}

static int TcpM_Send_Actual(TcpM *m, MsgContext *MsgCtx, int SingleServerIndex)
{
    char *Type;

    SocketPuller *p;
    TcpContext *TcpCtx;
    int i, NumOfServers, n = 0;

    IHeader *h = (IHeader *)MsgCtx;
    char *msg = (char *)(IHEADER_TAIL(h)) - 2;

    DNSSetTcpLength(msg, h->EntityLength);

    if( SingleServerIndex == -1 && m->Parallel )
    {
        NumOfServers = AddressList_GetNumberOfAddresses(&(m->ServiceList));
    } else {
        NumOfServers = 1;
    }

    p = &(m->QueryPuller);

    if( m->SocksProxies == NULL )
    {
        Type = "server";
    } else {
        Type = "proxy";
    }

    DEBUG("Send to Pullers[%d].\n", SingleServerIndex);

    if( TcpM_Connect(m, SingleServerIndex, FALSE) < 1 )
    {
        return 0;
    }

    for( i = 0; i < NumOfServers; ++i )
    {
        SOCKET s;
        int Err;
        struct timeval TimeOut = TimeOut_Const;

        s = p->Select(p, &TimeOut, (void **)&TcpCtx, FALSE, TRUE, &Err);

        if( s == INVALID_SOCKET )
        {
            if( Err != 0 && !ErrorOfVoidSelect(Err) )
            {
                ERRORMSG("TCP fatal error %d.\n", Err);
                break;
            }
            INFO("No %s TCP connection is established.\n", Type);
            continue;
        } else {
            p->Del(p, s);
        }

        if( m->SocksProxies != NULL && TcpCtx->Queried == 0 )
        {
            struct sockaddr *addr;
            sa_family_t family;

            addr = AddressList_GetOneBySubscript(&(m->ServiceList), &family, TcpCtx->ServerIndex);
            if( TcpM_ProxyPreparation(s, addr, family) != 0 )
            {
                AddressList_Advance(&(m->ServiceList));
                CLOSE_SOCKET(s);
                continue;
            }
        }

        if( TcpM_SendWrapper(s,
                             msg,
                             h->EntityLength + 2
                             )
            < 0 )
        {
            if( m->SocksProxies != NULL )
            {
                AddressList_Advance(&(m->ServiceList));
            }
            CLOSE_SOCKET(s);
            continue;
        }

        DEBUG("Sent by Pullers[%d].\n", TcpCtx->ServerIndex);

        TcpCtx->LastActivity = time(NULL);
        TcpCtx->Queried++;
        TcpCtx->MsgCtxQid = DNSGetQueryIdentifier(h + 1);
        TcpCtx->MsgCtxHash = h->HashValue;
        TcpCtx->MsgCtx = MsgCtx;
        m->Puller.Add(&(m->Puller), s, TcpCtx, sizeof(TcpContext));

        n++;
    }

    return n;
}

PUBFUNC int TcpM_Send(TcpM *m,
                      const char *Buffer,
                      int BufferLength
                      )
{
    int State;
    const IHeader *h = (IHeader *)Buffer;

    State = sendto(m->Incoming,
                   Buffer,
                   sizeof(IHeader) + h->EntityLength,
                   MSG_NOSIGNAL,
                   (const struct sockaddr *)&(m->IncomingAddr.Addr),
                   GetAddressLength(m->IncomingAddr.family)
                   );

    return !(State > 0);
}

static int TcpM_Cleanup(TcpM *m)
{
    m->IsServer = 0;

    CLOSE_SOCKET(m->Incoming);
    m->Incoming = INVALID_SOCKET;
    m->Puller.Free(&(m->Puller));

    ModuleContext_Free(&(m->Context));

    if( m->SocksProxies != NULL )
    {
        m->ProxyPuller.Free(&(m->ProxyPuller));
        SocketPullers_Free(m->Proxies);
        SafeFree(*(m->SocksProxies));
        AddressList_Free(&(m->SocksProxyList));
        SafeFree(m->SocksProxyFamilies);
    }

    m->QueryPuller.Free(&(m->QueryPuller));
    SocketPullers_Free(m->Agents);
    SafeFree(m->Services);
    AddressList_Free(&(m->ServiceList));
    SafeFree(m->ServiceFamilies);

    m->WorkThread = NULL_THREAD;

    return 0;
}

static int
#ifdef _WIN32
WINAPI
#endif
TcpM_Works(TcpM *m)
{
    int Err;

    char ReceiveBuffer[SOCKET_CONTEXT_LENGTH];
    MsgContext *MsgCtx;
    IHeader *Header;

    #define LEFT_LENGTH  (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))
    char *Entity;

    SocketPuller *p = &(m->Puller);
    TcpContext *TcpCtx;

    int NumberOfCumulated = 0;

    MsgCtx = (MsgContext *)ReceiveBuffer;
    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    while( m->IsServer )
    {
        SOCKET  s;
        struct timeval TimeOut = TimeOut_Const;

        s = p->Select(p, &TimeOut, (void **)&TcpCtx, TRUE, FALSE, &Err);

        if( s == INVALID_SOCKET )
        {
            if( Err != 0 )
            {
                ERRORMSG("TcpM fatal error %d.\n", Err);
                break;
            }
            m->Context.Sweep(&(m->Context), (SweepCallback)SweepWorks, m);
            NumberOfCumulated = 0;
            continue;
        }

        if( s == m->Incoming ) {
            int State;

            if( NumberOfCumulated > 1024 )
            {
                m->Context.Sweep(&(m->Context), (SweepCallback)SweepWorks, m);
                NumberOfCumulated = 0;
            }

            State = recvfrom(s,
                             ReceiveBuffer, /* Receiving a header */
                             SOCKET_CONTEXT_LENGTH,
                             0,
                             NULL,
                             NULL
                             );

            if( State > 0 )
            {
                MsgContext *MsgCtxStored;

                ++NumberOfCumulated;

                MsgCtxStored = m->Context.Add(&(m->Context), MsgCtx);
                if( MsgCtxStored == NULL )
                {
                    p->Del(p, s);
                    p->Add(p, s, TcpCtx, sizeof(TcpContext));
                    continue;
                }

                TcpM_Send_Actual(m, MsgCtxStored, -1);
            }

            p->Del(p, s);
            p->Add(p, s, TcpCtx, sizeof(TcpContext));

        } else {
            int State;
            uint16_t TCPLength;
            SocketPuller *p2;
            char *PartialData;

            p->Del(p, s);

            State = TcpM_RecvWrapper(s, (char *)&TCPLength, 2);
            if( State != 2 )
            {
                if( State < 1 )
                {
                    /* If Server force closed the keep-alive SOCKET: */
                    IHeader *Header2 = (IHeader *)TcpCtx->MsgCtx;
                    if( TcpCtx->Queried > 1 && Header2 != NULL && *(Header2->Domain) != 0 &&
                        TcpCtx->MsgCtxQid == DNSGetQueryIdentifier(Header2 + 1) &&
                        TcpCtx->MsgCtxHash == Header2->HashValue
                        )
                    {
                        INFO("TCP retrying for %s ...\n", Header2->Domain);
                        TcpM_Send_Actual(m, TcpCtx->MsgCtx, TcpCtx->ServerIndex);
                    }
                } else if( State == 1 )
                {
                    WARNING("TCP %s received bad data.\n",
                            m->SocksProxies != NULL ? "proxy" : "server");
                }
                CLOSE_SOCKET(s);
                continue;
            }

            TCPLength = ntohs(TCPLength);
            if( TCPLength > LEFT_LENGTH )
            {
                WARNING("TCP segment is too large, discarded.\n");
                CLOSE_SOCKET(s);
                continue;
            }

            PartialData = Entity;
            do
            {
                State = TcpM_RecvWrapper(s, PartialData, TCPLength);
                PartialData += State;
                TCPLength -= State;
            } while ( State > 0 && TCPLength > 0 );

            if( TCPLength != 0 )
            {
                WARNING("TCP %s received bad data, len: %d.\n",
                        m->SocksProxies != NULL ? "proxy" : "server", PartialData - Entity);
                CLOSE_SOCKET(s);
                continue;
            }

            p2 = m->Agents[TcpCtx->ServerIndex];
            TcpCtx->LastActivity = time(NULL);
            TcpCtx->MsgCtx = NULL;
            p2->Add(p2, s, TcpCtx, sizeof(TcpContext));

            IHeader_Fill(Header,
                         FALSE,
                         Entity,
                         State,
                         NULL,
                         INVALID_SOCKET,
                         AF_UNSPEC,
                         NULL
                         );

            switch( IPMiscMapping_Process(MsgCtx) )
            {
            case IP_MISC_NOTHING:
                break;

            case IP_MISC_FILTERED_IP:
                ShowBlockedMessage(Header, "Bad package, discarded");
                DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
                continue;
                break;

            case IP_MISC_NEGATIVE_RESULT:
                ShowBlockedMessage(Header, "Negative result, discarded");
                DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
                continue;
                break;

            default:
                ERRORMSG("Fatal error 155.\n");
                continue;
                break;
            }

            if( MsgContext_IsBlocked(MsgCtx) )
            {
                ShowBlockedMessage(Header, "False package, discarded");
                DomainStatistic_Add(Header, STATISTIC_TYPE_BLOCKEDMSG);
                continue;
            }

            State = m->Context.GenAnswerHeaderAndRemove(&(m->Context), MsgCtx, MsgCtx);

            DNSCache_AddItemsToCache(MsgCtx, State == 0);

            if( State != 0 )
            {
                continue;
            }

            if( MsgContext_SendBack(MsgCtx) != 0 )
            {
                ShowErrorMessage(Header, 'T');
                continue;
            }

            ShowNormalMessage(Header, 'T');
            DomainStatistic_Add(Header, STATISTIC_TYPE_TCP);
        }
    }

    TcpM_Cleanup(m);

    return 0;
}

int TcpM_Init(TcpM *m, const char *Services, BOOL Parallel, const char *SocksProxies)
{
    int ret;

    if( m == NULL || Services == NULL )
    {
        return -7;
    }

    if( ModuleContext_Init(&(m->Context), SOCKET_CONTEXT_LENGTH) != 0 )
    {
        return -12;
    }

    if( SocketPuller_Init(&(m->Puller), sizeof(TcpContext)) != 0 )
    {
        ret = -389;
        goto EXIT_1;
    }

    m->Incoming = TryBindLocal(Ipv6_Enabled, 10400, &(m->IncomingAddr));
    if( m->Incoming == INVALID_SOCKET )
    {
        ret = -357;
        goto EXIT_1;
    }

    m->Puller.Add(&(m->Puller), m->Incoming, NULL, 0);

    if( AddressList_Init(&(m->ServiceList)) != 0 )
    {
        ret = -17;
        goto EXIT_2;
    } else {
        StringList l;
        StringListIterator i;
        const char *Itr;

        if( StringList_Init(&l, Services, ", ") != 0 )
        {
            ret = -23;
            goto EXIT_2;
        }

        l.TrimAll(&l, "\t .");

        if( StringListIterator_Init(&i, &l) != 0 )
        {
            ret = -29;
            goto EXIT_2;
        }

        while( (Itr = i.Next(&i)) != NULL )
        {
            AddressList_Add_From_String(&(m->ServiceList), Itr, 53);
        }

        l.Free(&l);
    }

    m->Services = AddressList_GetPtrList(&(m->ServiceList),
                                         &(m->ServiceFamilies)
                                         );
    if( m->Services == NULL )
    {
        ret = -45;
        goto EXIT_3;
    }

    if( SocketPuller_Init(&(m->QueryPuller), sizeof(TcpContext) ) != 0 )
    {
        ret = -46;
        goto EXIT_4;
    }

    m->Agents = SocketPullers_Init( AddressList_GetNumberOfAddresses(&(m->ServiceList)), sizeof(TcpContext) );
    if( m->Agents == NULL )
    {
        ret = -47;
        goto EXIT_5;
    }

    if( SocksProxies == NULL )
    {
        m->SocksProxies = NULL;
        m->SocksProxyFamilies = NULL;
    } else {
        /* Proxied */
        if( AddressList_Init(&(m->SocksProxyList)) != 0 )
        {
            ret = -53;
            goto EXIT_6;
        } else {
            StringList l;
            StringListIterator i;
            const char *Itr;

            if( StringList_Init(&l, SocksProxies, ", ") != 0 )
            {
                ret = -61;
                goto EXIT_7;
            }

            l.TrimAll(&l, "\t .");

            if( StringListIterator_Init(&i, &l) != 0 )
            {
                l.Free(&l);
                ret = -58;
                goto EXIT_7;
            }

            while( (Itr = i.Next(&i)) != NULL )
            {
                AddressList_Add_From_String(&(m->SocksProxyList), Itr, 1080);
            }

            l.Free(&l);

            m->SocksProxies = AddressList_GetPtrList(&(m->SocksProxyList),
                                                      &(m->SocksProxyFamilies)
                                                      );

            if( m->SocksProxies == NULL )
            {
                ret = -84;
                goto EXIT_7;
            }

            if( SocketPuller_Init(&(m->ProxyPuller), sizeof(TcpContext)) != 0 )
            {
                ret = -85;
                goto EXIT_8;
            }

            m->Proxies = SocketPullers_Init( AddressList_GetNumberOfAddresses(&(m->SocksProxyList)), sizeof(TcpContext) );
            if( m->Proxies == NULL )
            {
                ret = -86;
                goto EXIT_9;
            }

        }
    }

    m->Send = TcpM_Send;

    m->ServiceName = Services;
    m->ProxyName = SocksProxies;
    m->Parallel = Parallel;
    m->IsServer = 1;

    CREATE_THREAD(TcpM_Works, m, m->WorkThread);
    DETACH_THREAD(m->WorkThread);

    return 0;

EXIT_9:
    m->ProxyPuller.FreeWithoutClose(&(m->ProxyPuller));
EXIT_8:
    SafeFree(*(m->SocksProxies));
EXIT_7:
    AddressList_Free(&(m->SocksProxyList));

EXIT_6:
    SocketPullers_Free(m->Agents);
EXIT_5:
    m->QueryPuller.FreeWithoutClose(&(m->QueryPuller));
EXIT_4:
    SafeFree(*(m->Services));

EXIT_3:
    AddressList_Free(&(m->ServiceList));
EXIT_2:
    m->Puller.Free(&(m->Puller));
EXIT_1:
    ModuleContext_Free(&(m->Context));
    return ret;
}
