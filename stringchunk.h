#ifndef STRINGCHUNK_H_INCLUDED
#define STRINGCHUNK_H_INCLUDED

#include "simpleht.h"
#include "stringlist.h"
#include "array.h"
#include "stablebuffer.h"

typedef struct _StringChunk{
    StringList  *List;

    /* Positions of every domain in `List' */
    SimpleHT    List_Pos;

    /* Positions of every domain in `List_W' */
    Array       List_W_Pos;

    /* Chunk of all additional datas */
    StableBuffer    AdditionalDataChunk;

} StringChunk;

typedef BOOL (*DataCompare)(const void **Data, const void *Expected);

int StringChunk_Init(StringChunk *dl, StringList *List);

int StringChunk_Add(StringChunk *dl,
                    const char *Str,
                    const void *AdditionalData,
                    int LengthOfAdditionalData
                    );

int StringChunk_Add_Domain(StringChunk  *dl,
                           const char   *Domain,
                           const void   *AdditionalData,
                           int          LengthOfAdditionalData /* The length will not be stored. */
                           );

/* NOTICE : Data address returned, not offset. */
BOOL StringChunk_Match_NoWildCard(StringChunk       *dl,
                                  const char        *Str,
                                  const uint32_t    *HashValue,
                                  void              **Data,
                                  DataCompare       cb,
                                  void              *Expected
                                  );

BOOL StringChunk_Match_OnlyWildCard(StringChunk *dl,
                                    const char  *Str,
                                    void        **Data,
                                    DataCompare cb,
                                    void        *Expected
                                    );

BOOL StringChunk_Match_OnlyWildCard_GetOne(StringChunk  *dl,
                                           const char   *Str,
                                           void         **Data,
                                           DataCompare  cb,
                                           void         *Expected
                                           );

BOOL StringChunk_Match(StringChunk      *dl,
                       const char       *Str,
                       const uint32_t   *HashValue,
                       void             **Data,
                       DataCompare      cb,
                       void             *Expected
                       );

BOOL StringChunk_Match_Exactly(StringChunk      *dl,
                               const char       *Str,
                               const uint32_t   *HashValue,
                               void             **Data,
                               DataCompare      cb,
                               void             *Expected
                               );

BOOL StringChunk_Domain_Match_NoWildCard(StringChunk    *dl,
                                         const char     *Domain,
                                         const uint32_t *HashValue,
                                         void           **Data,
                                         DataCompare    cb,
                                         void           *Expected
                                         );

/* Closest */
BOOL StringChunk_Domain_Match(StringChunk       *dl,
                              const char        *Domain,
                              const uint32_t    *HashValue,
                              void              **Data,
                              DataCompare       cb,
                              void              *Expected
                              );

BOOL StringChunk_Domain_Match_WildCardRandom(StringChunk    *dl,
                                             const char     *Domain,
                                             const uint32_t *HashValue,
                                             void           **Data,
                                             DataCompare    cb,
                                             void           *Expected
                                             );

const char *StringChunk_Enum_NoWildCard(StringChunk *dl, int32_t *Start, void **Data);

void StringChunk_Free(StringChunk *dl, BOOL FreeStringList);

int InitChunk(StringChunk **dl);

#endif /* STRINGCHUNK_H_INCLUDED */
