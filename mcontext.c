#include <string.h>
#include <time.h>
#include "mcontext.h"
#include "common.h"

static int ModuleContext_Sweep_Collect(Bst *t,
                                       const MsgContext *Context,
                                       Array *Pending
                                       )
{
    if( time(NULL) - ((IHeader *)Context)->Timestamp > 2 )
    {
        Array_PushBack(Pending, &Context, NULL);
    }

    return 0;
}

static void ModuleContext_Sweep(ModuleContext *c, SweepCallback cb, void *Arg)
{
    Array Pending;
    int i;

    if( Array_Init(&Pending,
                   sizeof(const MsgContext *),
                   4,
                   FALSE,
                   NULL
                   )
       != 0
       )
    {
        return;
    }

    c->d.Enum(&(c->d),
              (Bst_Enum_Callback)ModuleContext_Sweep_Collect,
              &Pending
              );

    for( i = 0; i < Array_GetUsed(&Pending); ++i )
    {
        const MsgContext **Context;

        Context = Array_GetBySubscript(&Pending, i);

        if( cb != NULL )
        {
            cb(*Context, i + 1, Arg);
        }

        c->d.Delete(&(c->d), *Context);
    }

    Array_Free(&Pending);
}

static MsgContext *ModuleContext_Add(ModuleContext *c, MsgContext *MsgCtx)
{
    IHeader *h;

    if( MsgCtx == NULL )
    {
        return NULL;
    }

    h = (IHeader *)MsgCtx;
    h->Timestamp = time(NULL);

    return (MsgContext *)(c->d.Add(&(c->d), MsgCtx));
}

static const MsgContext *ModuleContext_Find(ModuleContext *c, MsgContext *Input)
{
    return c->d.Search(&(c->d), Input, NULL);
}

static void ModuleContext_Del(ModuleContext *c, MsgContext *Input)
{
    c->d.Delete(&(c->d), Input);
}

static int ModuleContext_GenAnswerHeaderAndRemove(ModuleContext *c,
                                                  MsgContext *Input,
                                                  MsgContext *Output
                                                  )
{
    IHeader *h1, *h2;
    const MsgContext *ri;

    int EntityLength;
    BOOL EDNSEnabled;

    h1 = (IHeader *)Input;
    h2 = (IHeader *)Output;

    ri = ModuleContext_Find(c, Input);
    if( ri == NULL )
    {
        return -60;
    }

    EntityLength = h1->EntityLength;
    EDNSEnabled = h1->EDNSEnabled;

    memcpy(Output, ri, sizeof(IHeader));

    h2->EntityLength = EntityLength;
    h2->EDNSEnabled = EDNSEnabled;

    IHeader_Reset((IHeader *)ri);
    c->d.Delete(&(c->d), ri);

    return 0;
}

static int ModuleContextCompare(const void *_1, const void *_2)
{
    const IHeader *One = (IHeader *)_1;
    const IHeader *Two = (IHeader *)_2;
    int Id_1 = DNSGetQueryIdentifier(One + 1);
    int Id_2 = DNSGetQueryIdentifier(Two + 1);

    if( Id_1 != Id_2 )
    {
        return Id_1 - Id_2;
    } else {
        return One->HashValue - Two->HashValue;
    }
}

void ModuleContext_Free(ModuleContext *c)
{
    c->d.Free(&(c->d));
}

int ModuleContext_Init(ModuleContext *c, int ItemLength)
{
    if( c == NULL )
    {
        return -86;
    }

    if( Bst_Init(&(c->d), ItemLength, ModuleContextCompare) != 0 )
    {
        return -106;
    }

    c->Add = ModuleContext_Add;
    c->Del = ModuleContext_Del;
    c->Find = ModuleContext_Find;
    c->GenAnswerHeaderAndRemove = ModuleContext_GenAnswerHeaderAndRemove;
    c->Sweep = ModuleContext_Sweep;

    return 0;
}
