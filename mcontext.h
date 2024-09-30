#ifndef MCONTEXT_H_INCLUDED
#define MCONTEXT_H_INCLUDED
/** Thread unsafe */

#include "iheader.h"
#include "bst.h"

typedef void (*SweepCallback)(const MsgContext *MsgCtx, int Number, void *Arg);

typedef struct _ModuleContext ModuleContext;

struct _ModuleContext{
    /* private */
    Bst d;

    /* public */
    MsgContext *(*Add)(ModuleContext *c, MsgContext *MsgCtx);
    void (*Del)(ModuleContext *c, MsgContext *MsgCtx);
    const MsgContext *(*Find)(ModuleContext *c, MsgContext *Input);
    int (*GenAnswerHeaderAndRemove)(ModuleContext *c,
                                    MsgContext *Input,
                                    MsgContext *Output
                                    );

    void (*Sweep)(ModuleContext *c, SweepCallback cb, void *Arg);
};

void ModuleContext_Free(ModuleContext *c);

int ModuleContext_Init(ModuleContext *c, int ItemLength);

#endif /* MCONTEXT_H_INCLUDED */
