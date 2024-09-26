#ifndef IHEADER_H_INCLUDED
#define IHEADER_H_INCLUDED

#include "dnsrelated.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "utils.h"

typedef struct _IHeader IHeader;

typedef struct _MsgContext MsgContext;

struct _IHeader{
    IHeader     *Parent;    /* Solve CNAME hosts records. */
    BOOL        RequestTcp; /* Parent is from TCP. */
    time_t      Timestamp;

    Address_Type    BackAddress;    /* UDP requires it while TCP doesn't */
    SOCKET          SendBackSocket;

    char            Domain[256];
    uint32_t        HashValue;
    DNSRecordType   Type;

    BOOL            ReturnHeader;
    BOOL            EDNSEnabled;

    int             EntityLength;

    char            Agent[ROUND_UP(LENGTH_OF_IPV6_ADDRESS_ASCII + 1,
                                   sizeof(void *)
                                   )
                          ];

    uint16_t        TcpLengthRaw;   /* Place holder for sending TCP message. */
};

/* The **variable** context item structure:

struct _MsgContext{
    IHeader h;
    char    Entity[SOCKET_CONTEXT_LENGTH - sizeof(IHeader)];
};
*/

#define SOCKET_CONTEXT_LENGTH   4096

#define IHEADER_TAIL(ptr)   (void *)((IHeader *)(ptr) + 1)

void IHeader_Reset(IHeader *h);

int IHeader_Fill(IHeader *h,
                 BOOL ReturnHeader,
                 char *DnsEntity,
                 int EntityLength,
                 const struct sockaddr *BackAddress,
                 SOCKET SendBackSocket,
                 sa_family_t Family,
                 const char *Agent
                 );


int MsgContext_Init(BOOL _ap);

int MsgContext_AddFakeEdns(MsgContext *MsgCtx, int BufferLength);

BOOL MsgContext_IsBlocked(const MsgContext *MsgCtx);

BOOL MsgContext_IsFromTCP(const MsgContext *MsgCtx);

int MsgContext_SendBack(MsgContext *MsgCtx);

int MsgContext_SendBackRefusedMessage(MsgContext *MsgCtx);

#endif /* IHEADER_H_INCLUDED */
