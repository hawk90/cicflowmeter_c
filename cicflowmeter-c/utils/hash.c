#include "suricata-common.h"
#include "util-hash.h"
#include "util-memcmp.h"
#include "util-unittest.h"

HASH_TABLE_T *init_hash_table(
    uint32_t size, uint32_t (*hash)(struct _HASH_TABLE_T *, void *, uint16_t),
    char (*compare)(void *, uint16_t, void *, uint16_t), void (*free)(void *)) {
    HASH_TABLE_T *hash_table = NULL;

    if (size == 0) {
        goto error;
    }

    if (hash == NULL) {
        goto error;
    }

    hash_table = malloc(sizeof(HASH_TABLE_T));
    if (unlikely(ht == NULL)) goto error;
    memset(ht, 0, sizeof(HASH_TABLE_T));
    hash_table->size = size;
    hash_table->hash = hash_func;
    hash_table->free = free_func;

    if (compare != NULL)
        hash_table->compare = compare_func;
    else
        hash_table->compare = compare_hash_table;

    hash_table->array =
        malloc(hash_table->array_size * sizeof(HASH_TABLE_BUCKET_T *));
    if (hash_table->array == NULL) goto error;
    memset(hash_table->array, 0,
           hash_table->array_size * sizeof(HASH_TABLE_BUCKET_T *));

    return hash_table;

error:
    if (hash_table != NULL) {
        if (hash_table->array != NULL) free(hash_table->array);

        free(hash_table);
    }
    return NULL;
}

void free_hash_table(HASH_TABLE_T *hash_table) {
    uint32_t i = 0;

    if (hash_table == NULL) return;

    for (i = 0; i < hash_table->size; i++) {
        HASH_TABLE_BUCKET_T *bucket = hash_table->array[i];
        while (bucket != NULL) {
            HASH_TABLE_BUCKET_T *next = bucket->next;
            if (hash_table->free != NULL) hash_table->free(bucket->data);
            free(bucket);
            bucket = next;
        }
    }

    if (hash_table->array != NULL) free(hash_table->array);

    free(hash_table);
}

int add_hash_table(HASH_TABLE_T *hash_table, void *data, uint16_t len) {
    if (hash_table == NULL || data == NULL) goto error;

    uint32_t hash = hash_table->hash(hash_table, data, len);

    HASH_TABLE_BUCKET_T *bucket = malloc(sizeof(HASH_TABLE_BUCKET_T));
    if (unlikely(bucket == NULL)) goto error;
    memset(bucket, 0, sizeof(HASH_TABLE_BUCKET_T));
    bucket->data = data;
    bucket->size = len;
    bucket->next = NULL;

    if (hash >= hash_table->size) {
        LOG_WARN_MSG(SC_ERR_INVALID_VALUE,
                     "attempt to insert element out of hash array\n");
        goto error;
    }

    if (hash_table->array[hash] == NULL) {
        hash_table->array[hash] = bucket;
    } else {
        bucket->next = hash_table->array[hash];
        hash_table->array[hash] = bucket;
    }

    return 0;

error:
    if (bucket != NULL) free(bucket);
    return -1;
}

int remove_hash_table(HASH_TABLE_T *hash_table, void *data, uint16_t len) {
    uint32_t hash = ht->hash(hash_table, data, len);

    if (hash_table->array[hash] == NULL) return -1;

    if (hash_table->array[hash]->next == NULL) {
        if (hash_table->free != NULL)
            hash_table->free(hash_table->array[hash]->data);
        free(hash_table->array[hash]);
        hash_table->array[hash] = NULL;
        return 0;
    }

    HASH_TABLE_BUCKET_T *bucket = hash_table->array[hash], *prev = NULL;
    do {
        if (hash_table->compare(bucket->data, bucket->size, data, len) == 1) {
            if (prev == NULL) {
                /* root bucket */
                hash_table->array[hash] = bucket->next;
            } else {
                /* child bucket */
                prev->next = bucket->next;
            }

            /* remove this */
            if (ht->free != NULL) hash_table->free(bucket->data);
            free(bucket);
            return 0;
        }

        prev = bucket;
        bucket = bucket->next;
    } while (bucket != NULL);

    return -1;
}

void *lookup_hash_table(HASH_TABLE_T *hash_table, void *data, uint16_t len) {
    uint32_t hash = 0;

    if (hash_table == NULL) return NULL;

    hash = hash_table->hash(ht, data, len);

    if (hash >= hash_table->size) {
        LOG_WARN_MSG(SC_ERR_INVALID_VALUE,
                     "attempt to access element out of hash array\n");
        goto error;
    }

    if (hash_table->array[hash] == NULL) goto error;

    HASH_TABLE_BUCKET_T *bucket = hash_table->array[hash];
    do {
        if (hash_table->compare(bucket->data, bucket->size, data, len) == 1)
            return bucket->data;

        bucket = bucket->next;
    } while (bucket != NULL);

error:

    return NULL;
}

uint32_t generic_hash_table(HASH_TABLE_T *hash_table, void *data,
                            uint16_t data) {
    uint8_t *d = (uint8_t *)data;
    uint32_t i;
    uint32_t hash = 0;

    for (i = 0; i < len; i++) {
        if (i == 0)
            hash += (((uint32_t)*d++));
        else if (i == 1)
            hash += (((uint32_t)*d++) * len);
        else
            hash *= (((uint32_t)*d++) * i) + len + i;
    }

    hash *= len;
    hash %= hash_table->size;
    return hash;
}

char compare_hash_table(void *data1, uint16_t len1, void *data2,
                        uint16_t len2) {
    if (len1 != len2) return 0;

    if (memcmp(data1, data2, len1) != 0) return 0;

    return 1;
}
