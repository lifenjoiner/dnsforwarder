#include <string.h>
#include <time.h>
#include "stringchunk.h"
#include "utils.h"

typedef struct _EntryForString{
    const char  *str;
    void  *Data;
} EntryForString;

int StringChunk_Init(StringChunk *dl, StringList *List)
{
    int ret;

    if( dl == NULL )
    {
        return 0;
    }

    if( SimpleHT_Init(&(dl->List_Pos), sizeof(EntryForString), 5, HASH) != 0 )
    {
        return -1;
    }

    if( Array_Init(&(dl->List_W_Pos), sizeof(EntryForString), 0, FALSE, NULL) != 0 )
    {
        ret = -2;
        goto EXIT_1;
    }

    if( StableBuffer_Init(&(dl->AdditionalDataChunk)) != 0 )
    {
        ret = -3;
        goto EXIT_2;
    }

    /* Whether to use external `StringList' to store strings. */
    if( List == NULL )
    {
        dl->List = SafeMalloc(sizeof(StringList));
        if( dl->List == NULL )
        {
            ret = -4;
            goto EXIT_3;
        }

        if( StringList_Init(dl->List, NULL, NULL) != 0 )
        {
            ret = -5;
            goto EXIT_4;
        }
    } else {
        dl->List = List;
    }

    return 0;

EXIT_4:
    SafeFree(dl->List);
    dl->List = NULL;
EXIT_3:
    dl->AdditionalDataChunk.Free(&(dl->AdditionalDataChunk));
EXIT_2:
    SimpleHT_Free(&(dl->List_Pos));
EXIT_1:
    Array_Free(&(dl->List_W_Pos));
    return ret;
}

int StringChunk_Add(StringChunk *dl,
                    const char  *Str,
                    const void  *AdditionalData,
                    int         LengthOfAdditionalData /* The length will not be stored. */
                    )
{
    StableBuffer    *sb;
    StringList      *sl;

    SimpleHT        *nl;
    Array           *wl;

    EntryForString NewEntry;

    if( dl == NULL )
    {
        return FALSE;
    }

    sb = &(dl->AdditionalDataChunk);
    sl = dl->List;
    nl = &(dl->List_Pos);
    wl = &(dl->List_W_Pos);

    if( AdditionalData != NULL && LengthOfAdditionalData > 0 )
    {
        NewEntry.Data = sb->Add(sb,
                                AdditionalData,
                                LengthOfAdditionalData,
                                TRUE
                                );
        if( NewEntry.Data == NULL )
        {
            return -1;
        }
    } else {
        NewEntry.Data = NULL;
    }

    NewEntry.str = sl->Add(sl, Str, NULL);
    if( NewEntry.str == NULL )
    {
        return -2;
    }

    if( HAS_WILDCARD(Str) )
    {
        if( Array_PushBack(wl, &NewEntry, NULL) < 0 )
        {
            return -3;
        }
    } else {
        if( SimpleHT_Add(nl, Str, 0, (const char *)&NewEntry, NULL) == NULL )
        {
            return -4;
        }
    }

    return 0;
}

int StringChunk_Add_Domain(StringChunk  *dl,
                           const char   *Domain,
                           const void   *AdditionalData,
                           int          LengthOfAdditionalData /* The length will not be stored. */
                           )
{
    if( *Domain == '.' )
    {
        ++Domain;
    }

    return StringChunk_Add(dl, Domain, AdditionalData, LengthOfAdditionalData);
}

BOOL StringChunk_Match_NoWildCard(StringChunk       *dl,
                                  const char        *Str,
                                  const uint32_t    *HashValue,
                                  void              **Data,
                                  DataCompare       cb,
                                  void              *Expected
                                  )
{
    SimpleHT        *nl;

    EntryForString *FoundEntry = NULL;

    if( dl == NULL )
    {
        return FALSE;
    }

    nl = &(dl->List_Pos);

    while( FoundEntry = (EntryForString *)SimpleHT_Find(nl, Str, 0, HashValue, (const char *)FoundEntry),
            FoundEntry != NULL )
    {
        const char *FoundString;

        FoundString = FoundEntry->str;
        if( strcmp(FoundString, Str) == 0 )
        {
            if( Data != NULL )
            {
                if( cb != NULL && !cb(FoundEntry->Data, Expected) )
                {
                    continue;
                }
                *Data = FoundEntry->Data;
            }
            return TRUE;
        }
    }

    return FALSE;

}

BOOL StringChunk_Match_OnlyWildCard(StringChunk *dl,
                                    const char  *Str,
                                    void        **Data,
                                    DataCompare cb,
                                    void        *Expected
                                    )
{
    Array           *wl;

    EntryForString *FoundEntry;

    int loop;

    if( dl == NULL )
    {
        return FALSE;
    }

    wl = &(dl->List_W_Pos);

    for( loop = 0; loop != Array_GetUsed(wl); ++loop )
    {
        FoundEntry = (EntryForString *)Array_GetBySubscript(wl, loop);
        if( FoundEntry != NULL )
        {
            const char *FoundString = FoundEntry->str;
            if( WILDCARD_MATCH(FoundString, Str) == WILDCARD_MATCHED )
            {
                if( Data != NULL )
                {
                    if( cb != NULL && !cb(FoundEntry->Data, Expected) )
                    {
                        continue;
                    }
                    *Data = (void *)(FoundEntry->Data);
                }
                return TRUE;
            }

        } else {
            return FALSE;
        }
    }

    return FALSE;
}

BOOL StringChunk_Match_OnlyWildCard_GetOne(StringChunk  *dl,
                                           const char   *Str,
                                           void         **Data,
                                           DataCompare  cb,
                                           void         *Expected
                                           )
{
    Array           Matches;
    Array           MatchesAny;
    Array           *pm;
    Array           *wl;

    EntryForString *FoundEntry;

    int loop;

    if( dl == NULL )
    {
        return FALSE;
    }

    if( Array_Init(&Matches, sizeof(void *), 4, FALSE, NULL) != 0 )
    {
        return FALSE;
    }

    if( Array_Init(&MatchesAny, sizeof(void *), 4, FALSE, NULL) != 0 )
    {
        Array_Free(&Matches);
        return FALSE;
    }

    wl = &(dl->List_W_Pos);

    for( loop = 0; loop != Array_GetUsed(wl); ++loop )
    {
        FoundEntry = (EntryForString *)Array_GetBySubscript(wl, loop);
        if( FoundEntry != NULL )
        {
            const char *FoundString = FoundEntry->str;
            if( WILDCARD_MATCH(FoundString, Str) == WILDCARD_MATCHED )
            {
                if( cb != NULL && !cb(FoundEntry->Data, Expected) )
                {
                    continue;
                }
                Array_PushBack(strcmp(FoundString, "*") == 0 ? &MatchesAny : &Matches,
                               &(FoundEntry->Data),
                               NULL
                               );
            }
        }
    }

    pm = Array_GetUsed(&Matches) > 0 ? &Matches : &MatchesAny;

    if( Array_GetUsed(pm) > 0 )
    {
        srand(time(NULL));
        *Data = *((void **)Array_GetBySubscript(pm, rand() % Array_GetUsed(pm)));
    } else {
        *Data = NULL;
    }
    Array_Free(&MatchesAny);
    Array_Free(&Matches);

    return *Data != NULL;
}

BOOL StringChunk_Match(StringChunk      *dl,
                       const char       *Str,
                       const uint32_t   *HashValue,
                       void             **Data,
                       DataCompare      cb,
                       void             *Expected
                       )
{
    return (StringChunk_Match_NoWildCard(dl, Str, HashValue, Data, cb, Expected) ||
            StringChunk_Match_OnlyWildCard(dl, Str, Data, cb, Expected));
}

static BOOL StringChunk_Match_WildCard_Exactly(StringChunk  *dl,
                                               const char   *Str,
                                               void         **Data,
                                               DataCompare  cb,
                                               void         *Expected
                                               )
{
    Array           *wl;

    EntryForString *FoundEntry;

    int loop;

    if( dl == NULL )
    {
        return FALSE;
    }

    wl = &(dl->List_W_Pos);

    for( loop = 0; loop != Array_GetUsed(wl); ++loop )
    {
        FoundEntry = (EntryForString *)Array_GetBySubscript(wl, loop);
        if( FoundEntry != NULL )
        {
            const char *FoundString = FoundEntry->str;
            if( strcmp(Str, FoundString) == 0 )
            {
                if( Data != NULL )
                {
                    if( cb != NULL && !cb(FoundEntry->Data, Expected) )
                    {
                        continue;
                    }
                    *Data = (void *)(FoundEntry->Data);
                }
                return TRUE;
            }

        } else {
            return FALSE;
        }
    }

    return FALSE;
}

BOOL StringChunk_Match_Exactly(StringChunk      *dl,
                               const char       *Str,
                               const uint32_t   *HashValue,
                               void             **Data,
                               DataCompare      cb,
                               void             *Expected
                               )
{
    return (StringChunk_Match_NoWildCard(dl, Str, HashValue, Data, cb, Expected) ||
            StringChunk_Match_WildCard_Exactly(dl, Str, Data, cb, Expected));
}

BOOL StringChunk_Domain_Match_NoWildCard(StringChunk    *dl,
                                         const char     *Domain,
                                         const uint32_t *HashValue,
                                         void           **Data,
                                         DataCompare    cb,
                                         void           *Expected
                                         )
{
    if( dl == NULL )
    {
        return FALSE;
    }

    if( StringChunk_Match_NoWildCard(dl, Domain, HashValue, Data, cb, Expected) == TRUE )
    {
        return TRUE;
    }

    Domain = strchr(Domain + 1, '.');

    while( Domain != NULL )
    {
        if( StringChunk_Match_NoWildCard(dl, Domain + 1, NULL, Data, cb, Expected) == TRUE )
        {
            return TRUE;
        }

        Domain = strchr(Domain + 1, '.');
    }

    return FALSE;
}

BOOL StringChunk_Domain_Match(StringChunk       *dl,
                              const char        *Domain,
                              const uint32_t    *HashValue,
                              void              **Data,
                              DataCompare       cb,
                              void              *Expected
                              )
{
    return (StringChunk_Domain_Match_NoWildCard(dl, Domain, HashValue, Data, cb, Expected) ||
            StringChunk_Match_OnlyWildCard(dl, Domain, Data, cb, Expected));
}

BOOL StringChunk_Domain_Match_WildCardRandom(StringChunk    *dl,
                                             const char     *Domain,
                                             const uint32_t *HashValue,
                                             void           **Data,
                                             DataCompare    cb,
                                             void           *Expected
                                             )
{
    return (StringChunk_Domain_Match_NoWildCard(dl, Domain, HashValue, Data, cb, Expected) ||
            StringChunk_Match_OnlyWildCard_GetOne(dl, Domain, Data, cb, Expected));
}

/* Start by 0 */
const char *StringChunk_Enum_NoWildCard(StringChunk *dl, int32_t *Start, void **Data)
{
    EntryForString *Result;

    Result = (EntryForString *)SimpleHT_Enum(&(dl->List_Pos), Start);
    if( Result == NULL )
    {
        if( Data != NULL )
        {
            *Data = NULL;
        }

        return NULL;
    }

    if( Data != NULL )
    {
        *Data = (void *)Result->Data;
    }

    return Result->str;
}

void StringChunk_Free(StringChunk *dl, BOOL FreeStringList)
{
    SimpleHT_Free(&(dl->List_Pos));
    Array_Free(&(dl->List_W_Pos));
    dl->AdditionalDataChunk.Free(&(dl->AdditionalDataChunk));

    if( FreeStringList == TRUE )
    {
        dl->List->Free(dl->List);
        SafeFree(dl->List);
    }
}

int InitChunk(StringChunk **dl)
{
    if( *dl != NULL )
    {
        return 0;
    }

    *dl = malloc(sizeof(StringChunk));
    if( *dl == NULL )
    {
        return -77;
    }

    if( StringChunk_Init(*dl, NULL) < 0 )
    {
        free(*dl);
        *dl = NULL;
        return -82;
    }

    return 0;
}
