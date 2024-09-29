#ifndef HASHTABLE_H_INCLUDED
#define HASHTABLE_H_INCLUDED

#include <time.h>
#include "array.h"

typedef struct _Cht_Node{
    int32_t     Slot;
    int32_t     Next;
    int32_t     Offset;
    uint32_t    TTL;
    time_t      TimeAdded;
    uint32_t    Length;
    uint32_t    UsedLength;
} Cht_Node;

typedef struct _Cht_2DList{
    int32_t     KeyNext;
    int32_t     ValNext;
    int32_t     ReservedOffset;
    int32_t     ReservedTTL;    /* for sweepping thread */
    time_t      TimeAdded;
    uint32_t    ReservedLength;
    int32_t     Count;
} Cht_2DList;

typedef struct _HashTable{
    Array   NodeChunk;
    Array   Slots;
    int32_t Free2DList;
}CacheHT;

int CacheHT_Init(CacheHT *h, char *BaseAddr, int CacheSize);

int CacheHT_ReInit(CacheHT *h, char *BaseAddr, int CacheSize);

int32_t CacheHT_FindUnusedNode(CacheHT      *h,
                               uint32_t    ChunkSize,
                               Cht_Node    **Out,
                               void        *Boundary,
                               BOOL        *NewCreated
                               );

int CacheHT_InsertToSlot(CacheHT    *h,
                         const char *Key,
                         int        Node_index,
                         Cht_Node   *Node,
                         const uint32_t *HashValue
                         );

int CacheHT_RemoveFromSlot(CacheHT *h, int32_t SubScriptOfNode, Cht_Node *Node);

Cht_Node *CacheHT_Get(CacheHT *h, const char *Key, const Cht_Node *Start, const uint32_t *HashValue);

void CacheHT_Free(CacheHT *h);

#endif /* HASHTABLE_H_INCLUDED */
