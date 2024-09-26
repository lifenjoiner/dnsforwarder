#include "tcpfrontend.h"
#include "socketpuller.h"
#include "addresslist.h"
#include "utils.h"
#include "mmgr.h"
#include "logs.h"

extern BOOL Ipv6_Enabled;

static SocketPuller Frontend;

static void
#ifdef WIN32
WINAPI
#endif
TcpFrontend_Work(void *Unused)
{
    char *ReceiveBuffer;
    IHeader *Header;

    #define LEFT_LENGTH  (SOCKET_CONTEXT_LENGTH - sizeof(IHeader))
    char *Entity;

    ReceiveBuffer = SafeMalloc(SOCKET_CONTEXT_LENGTH);
    if( ReceiveBuffer == NULL )
    {
        ERRORMSG("No enough memory, 26.\n");
        return;
    }

    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    /* Loop */
    while( TRUE )
    {
        SOCKET sock, sock_c;
        Address_Type *ClientAddr, ClientAddr_c;
        BOOL IsNewConnected;

        int RecvState;
        uint16_t TCPLength;

        char Agent[sizeof(Header->Agent)];

        sock = Frontend.Select(&Frontend,
                               NULL,
                               (void **)&ClientAddr,
                               TRUE,
                               FALSE,
                               NULL
                               );

        if( sock == INVALID_SOCKET )
        {
            ERRORMSG("Fatal error 58.\n");
            break;
        }

        if( ((struct sockaddr *)ClientAddr)->sa_family == AF_UNSPEC )
        {
            socklen_t AddrLen = sizeof(Address_Type);

            sock_c = accept(sock, (struct sockaddr *)&(ClientAddr_c.Addr), &AddrLen);
            if(sock_c == INVALID_SOCKET)
            {
                continue;
            }

            IsNewConnected = TRUE;
            ClientAddr_c.family = ClientAddr->family;
            ClientAddr = &ClientAddr_c;
        } else {
            IsNewConnected = FALSE;
            sock_c = sock;
        }

        if( ClientAddr->family == AF_INET )
        {
            IPv4AddressToAsc(&(((struct sockaddr_in *)ClientAddr)->sin_addr), Agent);
        } else {
            IPv6AddressToAsc(&(((struct sockaddr_in6 *)ClientAddr)->sin6_addr), Agent);
        }

        RecvState = recv(sock_c, (char *)&TCPLength, 2, 0);
        if( RecvState == 2 )
        {
            TCPLength = ntohs(TCPLength);
            if( TCPLength <= LEFT_LENGTH )
            {
                RecvState = recv(sock_c, Entity, TCPLength, 0);
                if( RecvState == TCPLength )
                {
                    IHeader_Fill(Header,
                                 FALSE,
                                 Entity,
                                 RecvState,
                                 NULL,
                                 sock_c,
                                 ClientAddr->family,
                                 Agent
                                 );

                    MMgr_Send(ReceiveBuffer, SOCKET_CONTEXT_LENGTH);

                    if( IsNewConnected )
                    {
                        Frontend.Add(&Frontend, sock_c, ClientAddr, sizeof(Address_Type));
                    }

                    continue;

                } else {
                    INFO("Invalid data received from TCP client %s.\n", Agent);
                }
            } else {
                WARNING("TCP client %s segment is too large, discarded.\n", Agent);
            }

            CLOSE_SOCKET(sock_c);
        } else if( RecvState == 1 )
        {
            INFO("Invalid data received from TCP client %s.\n", Agent);
            CLOSE_SOCKET(sock_c);
        }

        /* recv failed */
        if( IsNewConnected == FALSE )
        {
            Frontend.Del(&Frontend, sock_c);
        }
    }

    SafeFree(ReceiveBuffer);
}

void TcpFrontend_StartWork(void)
{
    ThreadHandle t;

    CREATE_THREAD(TcpFrontend_Work, NULL, t);
    DETACH_THREAD(t);
}

static void TcpFrontend_Cleanup(void)
{
    Frontend.Free(&Frontend);
}

int TcpFrontend_Init(ConfigFileInfo *ConfigInfo, BOOL StartWork)
{
    StringList *TCPLocal;
    StringListIterator i;
    const char *One;

    int Count = 0;

    TCPLocal = ConfigGetStringList(ConfigInfo, "TCPLocal");
    if( TCPLocal == NULL )
    {
        WARNING("No TCP interface specified.\n");
        return -11;
    }

    if( StringListIterator_Init(&i, TCPLocal) != 0 )
    {
        return -20;
    }

    if( SocketPuller_Init(&Frontend, sizeof(Address_Type)) != 0 )
    {
        return -19;
    }

    while( (One = i.Next(&i)) != NULL )
    {
        Address_Type a, ClientAddr;
        sa_family_t f;

        SOCKET sock;

        f = AddressList_ConvertFromString(&a, One, 53);
        if( f == AF_UNSPEC )
        {
            ERRORMSG("Invalid TCPLocal option: %s .\n", One);
            continue;
        }

        sock = socket(f, SOCK_STREAM, IPPROTO_TCP);
        if( sock == INVALID_SOCKET )
        {
            continue;
        }

        if( bind(sock,
                 (const struct sockaddr *)&(a.Addr),
                 GetAddressLength(f)
                 )
            != 0 )
        {
            char p[128];

            snprintf(p, sizeof(p), "Opening TCP interface %s failed", One);
            p[sizeof(p) - 1] = '\0';

            ShowSocketError(p, GET_LAST_ERROR());
            CLOSE_SOCKET(sock);
            continue;
        }

        if( listen(sock, 16) == SOCKET_ERROR )
        {
            ERRORMSG("Can't listen on interface: %s .\n", One);
            break;
        }

        if( f == AF_INET6 )
        {
            Ipv6_Enabled = TRUE;
        }

        memset(&ClientAddr, 0, sizeof(Address_Type));
        ClientAddr.family = f;
        Frontend.Add(&Frontend, sock, &ClientAddr, sizeof(Address_Type));
        INFO("TCP interface %s opened.\n", One);
        ++Count;
    }

    atexit(TcpFrontend_Cleanup);

    if( Count == 0 )
    {
        ERRORMSG("No TCP interface opened.\n");
        return -163;
    }

    if( StartWork )
    {
        TcpFrontend_StartWork();
    }

    return 0;
}
