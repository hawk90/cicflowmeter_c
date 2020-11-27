#ifndef __cicflowmeter_utils_hash_h__
#define __cicflowmeter_utils_hash_h__

#ifdef __cplusplus
extern "C" {
#endif

/* hash bucket structure */
typedef struct _HASH_TABLE_BUCKET_T {
    void *data;
    uint16_t size;
    struct _HASH_TABLE_BUCKET_T *next;
} HASH_TABLE_BUCKET_T;

/* hash table structure */
typedef struct _HASH_TABLE_T {
    HASH_TABLE_BUCKET_T **array;
    uint32_t size;
    uint32_t (*hash)(struct _HASH_TABLE_T *, void *, uint16_t);
    char (*compare)(void *, uint16_t, void *, uint16_t);
    void (*free)(void *);
} HASH_TABLE_T;

#define HASH_NO_SIZE 0

/* prototypes */
HASH_TABLE_T *init_hash_table(
    uint32_t, uint32_t (*hash)(struct _HASH_TABLE_T *, void *, uint16_t),
    char (*compare)(void *, uint16_t, void *, uint16_t), void (*free)(void *));
void free_hash_table(HASH_TABLE_T *);
int add_hash_table(HASH_TABLE_T *, void *, uint16_t);
int remove_hash_table(HASH_TABLE_T *, void *, uint16_t);
void *lookup_hash_table(HASH_TABLE_T *, void *, uint16_t);
uint32_t generic_hash_table(HASH_TABLE_T *, void *, uint16_t);
char compare_hash_table(void *, uint16_t, void *, uint16_t);

#ifdef __cplusplus
}
#endif

#endif
