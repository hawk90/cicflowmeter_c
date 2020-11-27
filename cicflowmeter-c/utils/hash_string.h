#ifndef __CICFLOWMETER_UTILS_HASH_STRING_H__
#define __CICFLOWMETER_UTILS_HASH_STRING_H__

#ifdef __cplusplus
extern "c" {
#endif

uint32_t hash_string(HASH_TABLE_T *hash_table, void *data, uint16_t data);
char compare_string_hash(void *data1, uint16_t len1, void *data2,
                         uint16_t len2);
void free_string_hash(void *data);

#ifdef __cplusplus
}
#endif

#endif
