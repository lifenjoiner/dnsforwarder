#include <string.h>
#include <time.h>
#include "udpm.h"
#include "logs.h"
#include "utils.h"
#include "dnscache.h"
#include "ipmisc.h"
#include "domainstatistic.h"
#include "timedtask.h"

static void SweepWorks(MsgContext *MsgCtx, int Number, UdpM *Module)
{
    IHeader *h = (IHeader *)MsgCtx;

    ShowTimeOutMessage(h, 'U');
    DomainStatistic_Add(h, STATISTIC_TYPE_REFUSED);
    ++(Module->CountOfTimeout);

    if( Number == 1 )
    {
        AddressList_Advance(&(Module->AddrList));
    }
}

static int SwepTask(UdpM *m, SwepCallback cb)
{
    EFFECTIVE_LOCK_GET(m->Lock);
    m->Context.Swep(&(m->Context), cb, m);
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    return 0;
}

static int
#ifdef _WIN32
WINAPI
#endif
UdpM_Swep_Thread(UdpM *m)
{
    while( m->IsServer || m->WorkThread != NULL_THREAD)
    {
        SwepTask(m, (SwepCallback)SweepWorks);
        SLEEP(10000);
    }

    ModuleContext_Free(&(m->Context));
    EFFECTIVE_LOCK_DESTROY(m->Lock);

    m->SwepThread = NULL_THREAD;

    return 0;
}

static int UdpM_Cleanup(UdpM *m)
{
    m->IsServer = 0;

    CLOSE_SOCKET(m->Departure);
    m->Departure = INVALID_SOCKET;

    SafeFree(m->Parallels.addrs);
    AddressList_Free(&(m->AddrList));

    m->WorkThread = NULL_THREAD;

    return 0;
}

static void
#ifdef _WIN32
WINAPI
#endif
UdpM_Works(UdpM *m)
{
    static const struct timeval ShortTime = {10, 0};
    struct timeval Timeout;

    struct sockaddr *addr;

    char ReceiveBuffer[SOCKET_CONTEXT_LENGTH];
    MsgContext *MsgCtx;
    IHeader *Header;

    #define LEFT_LENGTH  (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))
    char *Entity;

    fd_set  ReadSet, ReadySet;

    /* Make analyzer happy. */
    FD_ZERO(&ReadSet);

    MsgCtx = (MsgContext *)ReceiveBuffer;
    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    while( m->IsServer )
    {
        int RecvState;
        int ContextState;

        /* Set up socket */
        if( m->Departure == INVALID_SOCKET )
        {
            sa_family_t family;

            EFFECTIVE_LOCK_GET(m->Lock);
            if( m->Parallels.addrs == NULL )
            {
                addr = AddressList_GetOne(&(m->AddrList), &family);
                if( addr == NULL )
                {
                    ERRORMSG("Fatal error 53.\n");
                    EFFECTIVE_LOCK_RELEASE(m->Lock);
                    break;
                }

            } else { /* Parallel query */
                family = m->Parallels.familiy;
            }
            m->Departure = socket(family, SOCK_DGRAM, IPPROTO_UDP);

            if( m->Departure == INVALID_SOCKET )
            {
                ERRORMSG("Fatal error 68.\n");
                EFFECTIVE_LOCK_RELEASE(m->Lock);
                break;
            }

#if defined(_WIN32) && defined(IPV6_V6ONLY)
            if( family == AF_INET6 )
            {
                SetSocketIPv6V6only(m->Departure, 0);
            }
#endif

            m->CountOfTimeout = 0;

            EFFECTIVE_LOCK_RELEASE(m->Lock);

            FD_ZERO(&ReadSet);
            FD_SET(m->Departure, &ReadSet);
        }

        ReadySet = ReadSet;
        Timeout = ShortTime;
        switch( select(m->Departure + 1, &ReadySet, NULL, NULL, &Timeout) )
        {
            case SOCKET_ERROR:
                WARNING("SOCKET_ERROR reached, 98.\n");
                FD_CLR(m->Departure, &ReadSet);
                CLOSE_SOCKET(m->Departure);
                m->Departure = INVALID_SOCKET;
                continue;
                break;

            case 0:
                #define RECREATION_THRESHOLD    8
                if( m->CountOfTimeout > RECREATION_THRESHOLD )
                {
                    FD_CLR(m->Departure, &ReadSet);
                    CLOSE_SOCKET(m->Departure);
                    m->Departure = INVALID_SOCKET;

                    WARNING("UDP socket is about to be recreated.\n");
                }
                continue;
                break;

            default:
                /* Goto recv job */
                break;
        }

        /* recv */
        RecvState = recvfrom(m->Departure,
                             Entity,
                             LEFT_LENGTH,
                             0,
                             NULL,
                             NULL
                             );

        if( RecvState <= 0 )
        {
            ERRORMSG("recvfrom %s error: %d\n", m->ServiceName, RecvState);
            continue;
        }

        m->CountOfTimeout = 0;

        /* Fill IHeader */
        IHeader_Fill(Header,
                     FALSE,
                     Entity,
                     RecvState,
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

        /* Fetch context item */
        EFFECTIVE_LOCK_GET(m->Lock);
        ContextState = m->Context.GenAnswerHeaderAndRemove(&(m->Context), MsgCtx, MsgCtx);
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        DNSCache_AddItemsToCache(MsgCtx, ContextState == 0);

        if( ContextState != 0 )
        {
            continue;
        }

        if( MsgContext_SendBack(MsgCtx) != 0 )
        {
            ShowErrorMessage(Header, 'U');
            continue;
        }

        ShowNormalMessage(Header, 'U');
        DomainStatistic_Add(Header, STATISTIC_TYPE_UDP);
    }

    UdpM_Cleanup(m);
}

static int UdpM_Send(UdpM *m,
                     const char *Buffer,
                     int BufferLength
                     )
{
    int ret = 0;
    const IHeader *h = (IHeader *)Buffer;

    MsgContext_AddFakeEdns((MsgContext *)Buffer, BufferLength);

    EFFECTIVE_LOCK_GET(m->Lock);
    if( m->Context.Add(&(m->Context), (MsgContext *)Buffer) == NULL )
    {
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        return -242;
    }
    EFFECTIVE_LOCK_RELEASE(m->Lock);

    if( m->Departure != INVALID_SOCKET )
    {
        if( m->Parallels.addrs != NULL )
        { /* Parallel query */
            struct sockaddr **a = m->Parallels.addrs;

            while( *a != NULL )
            {
                int State;

                State = sendto(m->Departure,
                               (const void *)(h + 1),
                               h->EntityLength,
                               MSG_NOSIGNAL,
                               *a,
                               m->Parallels.addrlen
                               );

                ret |= (State > 0);

                ++a;
            }

        } else {
            struct sockaddr *a;
            sa_family_t family;

            int State;

            a = AddressList_GetOne(&(m->AddrList), &family);
            if( a == NULL )
            {
                ERRORMSG("Fatal error 205.\n");
                return -277;
            }

            State = sendto(m->Departure,
                           (const void *)(h + 1),
                           h->EntityLength,
                           MSG_NOSIGNAL,
                           a,
                           GetAddressLength(family)
                           );

            ret = (State > 0);

            /** TODO: Error handlings */

        }
    }

    /*EFFECTIVE_LOCK_RELEASE(m->Lock);*/
    return !ret;
}

int UdpM_Init(UdpM *m, const char *Services, BOOL Parallel)
{
    StringList  Addresses;
    StringListIterator  sli;
    const char *Itr;
    int ret;

    if( m == NULL || Services == NULL )
    {
        return -141;
    }

    m->Departure = INVALID_SOCKET;
    if( StringList_Init(&Addresses, Services, ", ") != 0 )
    {
        return -364;
    }

    Addresses.TrimAll(&Addresses, "\t .");

    if( StringListIterator_Init(&sli, &Addresses) != 0 )
    {
        ret = -169;
        goto EXIT_1;
    }

    if( AddressList_Init(&(m->AddrList)) != 0 )
    {
        ret = -171;
        goto EXIT_1;
    }

    Itr = sli.Next(&sli);
    while( Itr != NULL )
    {
        AddressList_Add_From_String(&(m->AddrList), Itr, 53);
        Itr = sli.Next(&sli);
    }

    Addresses.Free(&Addresses);

    if( Parallel )
    {
        if( AddressList_GetOneBySubscript(&(m->AddrList),
                                          &(m->Parallels.familiy),
                                          0
                                          )
           == NULL )
        {
            ret = -184;
            goto EXIT_2;
        }

        m->Parallels.addrs =
            AddressList_GetPtrListOfFamily(&(m->AddrList),
                                           m->Parallels.familiy
                                           );

        m->Parallels.addrlen = GetAddressLength(m->Parallels.familiy);

    } else {
        m->Parallels.addrs = NULL;
        m->Parallels.familiy = AF_UNSPEC;
        m->Parallels.addrlen = 0;
    }

    if( ModuleContext_Init(&(m->Context), SOCKET_CONTEXT_LENGTH) != 0 )
    {
        ret = -143;
        goto EXIT_3;
    }

    m->CountOfTimeout = 0;

    m->ServiceName = Services;
    m->IsServer = 1;

    EFFECTIVE_LOCK_INIT(m->Lock);

    m->Send = UdpM_Send;

    CREATE_THREAD(UdpM_Works, m, m->WorkThread);
    DETACH_THREAD(m->WorkThread);
    CREATE_THREAD(UdpM_Swep_Thread, m, m->SwepThread);
    DETACH_THREAD(m->SwepThread);

    return 0;

EXIT_3:
    SafeFree(m->Parallels.addrs);
EXIT_2:
    AddressList_Free(&(m->AddrList));
    return ret;

EXIT_1:
    Addresses.Free(&Addresses);
    return ret;
}
