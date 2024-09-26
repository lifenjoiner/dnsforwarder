#include <string.h>
#include <math.h>
#include "cacheht.h"
#include "common.h"
#include "utils.h"
#include "logs.h"

static int32_t  FreeNodeCount = 0;

typedef struct _Cht_Slot{
    int32_t Next;
} Cht_Slot;

static int CacheHT_CalculateSlotCount(int CacheSize)
{
    int PreValue;
    if( CacheSize < 1048576 )
    {
        PreValue = CacheSize / 4979 - 18;
    } else {
        PreValue = pow(log((double)CacheSize), 2);
    }

    return ROUND(PreValue, 10) + 7;
}

int CacheHT_Init(CacheHT *h, char *BaseAddr, int CacheSize)
{
    int loop;

    h->Slots.Used = CacheHT_CalculateSlotCount(CacheSize);
    h->Slots.DataLength = sizeof(Cht_Slot);
    h->Slots.Data = BaseAddr + CacheSize - (h->Slots.DataLength) * (h->Slots.Used);
    h->Slots.Allocated = h->Slots.Used;

    for(loop = 0; loop != h->Slots.Allocated; ++loop)
    {
        ((Cht_Slot *)Array_GetBySubscript(&(h->Slots), loop))->Next = -1;
    }

    h->NodeChunk.DataLength = sizeof(Cht_Node);
    h->NodeChunk.Data = h->Slots.Data - h->NodeChunk.DataLength;
    h->NodeChunk.Used = 0;
    h->NodeChunk.Allocated = -1;

    h->FreeList = -1;

    return 0;
}

int CacheHT_ReInit(CacheHT *h, char *BaseAddr, int CacheSize)
{
    h->Slots.Data = BaseAddr + CacheSize - (h->Slots.DataLength) * (h->Slots.Used);
    h->NodeChunk.Data = h->Slots.Data - h->NodeChunk.DataLength;

    return 0;
}

static int CacheHT_CreateNewNode(CacheHT *h, uint32_t ChunkSize, Cht_Node **Out, void *Boundary)
{
    int         NewNode_i;
    Cht_Node    *NewNode;

    Array       *NodeChunk = &(h->NodeChunk);

    NewNode_i = Array_PushBack(NodeChunk, NULL, Boundary);
    if( NewNode_i < 0 )
    {
        return -1;
    }

    NewNode = (Cht_Node *)Array_GetBySubscript(NodeChunk, NewNode_i);
    NewNode->Next = -1;

    NewNode->Length = ChunkSize;
    NewNode->UsedLength = 0;

    if( Out != NULL )
    {
        *Out = NewNode;
    }

    return NewNode_i;
}

int32_t CacheHT_FindUnusedNode(CacheHT      *h,
                               uint32_t     ChunkSize,
                               Cht_Node     **Out,
                               void         *Boundary,
                               BOOL         *NewCreated
                               )
{
    int32_t Subscript = h->FreeList;
    Cht_Node    *FirstNode = NULL;
    Cht_Node    *SecondNode = NULL;
    int count = 0;

    const Array *NodeChunk = &(h->NodeChunk);

    DEBUG("CacheHT free nodes: %d\n", FreeNodeCount);
    while ( Subscript >= 0 )
    {
        FirstNode = SecondNode;
        SecondNode = (Cht_Node *)Array_GetBySubscript(NodeChunk, Subscript);
        ++count;
        if( SecondNode->Length == ChunkSize )
        {
            if( FirstNode == NULL )
            {
                h->FreeList = SecondNode->Next;
            } else {
                FirstNode->Next = SecondNode->Next;
            }

            SecondNode->UsedLength = 0;
            SecondNode->Next = -1;

            if( Out != NULL )
            {
                *Out = SecondNode;
            }

            *NewCreated = FALSE;
            --FreeNodeCount;
            DEBUG("CacheHT free node reused: %d\n", count);

            return Subscript;
        }

        Subscript = SecondNode->Next;
    }

    *NewCreated = TRUE;
    return CacheHT_CreateNewNode(h, ChunkSize, Out, Boundary);
}

int CacheHT_InsertToSlot(CacheHT    *h,
                         const char *Key,
                         int        Node_index,
                         Cht_Node   *Node,
                         const uint32_t *HashValue
                         )
{
    int         Slot_i;
    Cht_Slot    *Slot;

    if( h == NULL || Key == NULL || Node_index < 0 || Node == NULL )
        return -1;

    if( HashValue != NULL )
    {
        Slot_i = (*HashValue) % (h->Slots.Allocated);
    } else {
        Slot_i = HASH(Key, 0) % (h->Slots.Allocated);
    }

    Node->Slot = Slot_i;

    Slot = (Cht_Slot *)Array_GetBySubscript(&(h->Slots), Slot_i);
    if( Slot == NULL )
        return -2;

    Node->Next = Slot->Next;
    Slot->Next = Node_index;

    return 0;
}

static Cht_Node *CacheHT_FindPredecessor(CacheHT *h, const Cht_Slot *Slot, int32_t SubScriptOfNode)
{
    int Next = Slot->Next;
    Cht_Node *Node;

    if( Next == SubScriptOfNode )
    {
        return NULL;
    }

    while( Next >= 0 )
    {
        Node = Array_GetBySubscript(&(h->NodeChunk), Next);
        Next = Node->Next;

        if( Next == SubScriptOfNode )
        {
            return Node;
        }
    }

    return NULL;
}

int CacheHT_RemoveFromSlot(CacheHT *h, int32_t SubScriptOfNode, Cht_Node *Node)
{
    Array       *NodeChunk = &(h->NodeChunk);
    Cht_Slot    *Slot;
    Cht_Node    *Predecessor;

    if( Node->Slot < 0 )
    {
        return 0;
    }

    Slot = (Cht_Slot *)Array_GetBySubscript(&(h->Slots), Node->Slot);
    if( Slot == NULL )
    {
        return -1;
    }

    Predecessor = CacheHT_FindPredecessor(h, Slot, SubScriptOfNode);
    if( Predecessor == NULL )
    {
        Slot->Next = Node->Next;
    } else {
        Predecessor->Next = Node->Next;
    }

    /* If this node is not the last one of NodeChunk, add it into free list,
     * or simply delete it from NodeChunk
     */
    if( SubScriptOfNode != NodeChunk->Used - 1 )
    {
        Node->Next = h->FreeList;
        h->FreeList = SubScriptOfNode;
        Node->Slot = -1;
        ++FreeNodeCount;
    } else {
        --(NodeChunk->Used);
    }

    return 0;
}

Cht_Node *CacheHT_Get(CacheHT *h, const char *Key, const Cht_Node *Start, const uint32_t *HashValue)
{
    Cht_Node    *Node;

    if( h == NULL || Key == NULL)
        return NULL;

    if( Start == NULL )
    {
        int         Slot_i;
        Cht_Slot    *Slot;

        if( HashValue != NULL )
        {
            Slot_i = (*HashValue) % (h->Slots.Allocated);
        } else {
            Slot_i = HASH(Key, 0) % (h->Slots.Allocated);
        }

        Slot = (Cht_Slot *)Array_GetBySubscript(&(h->Slots), Slot_i);

        Node = (Cht_Node *)Array_GetBySubscript(&(h->NodeChunk), Slot->Next);
        if( Node == NULL )
            return NULL;

        return Node;

    } else {
        Node = (Cht_Node *)Array_GetBySubscript(&(h->NodeChunk), Start->Next);
        if( Node == NULL )
            return NULL;

        return Node;
    }

}

void CacheHT_Free(CacheHT *h)
{
    Array_Free(&(h->NodeChunk));
    Array_Free(&(h->Slots));
    h->FreeList = -1;
}
