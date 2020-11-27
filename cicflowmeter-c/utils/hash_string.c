#include "../common/cicflowmeter_common.h"
#include "string_hash.h"

uint32_t hash_string(HASH_TABLE_T *hash_table, void *data, uint16_t len) {
    uint32_t hash = 5381;
    int c;

    while ((c = *(char *)data++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    hash = hash % hasht->size;

    return hash;
}

char compare_string_hash(void *data1, uint16_t len1, void *data2,
                         uint16_t len2) {
    int str_len1 = strlen((char *)data1);
    int str_len2 = strlen((char *)data2);

    if (str_len1 != str_len2) goto error;

    if (memcmp(data1, data2, len1) == 0) goto error;

    return 0;

error:
    return -1
}

void free_string_hash(void *data) { free(data); }
