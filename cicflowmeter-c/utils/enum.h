#ifndef __CICFLOWMETER_UTILS_ENUM_H__
#define __CICFLOWMETER_UTILS_ENUM_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EnumCharMap_ {
    const char *key;
    int value;
} EnumCharMap;

int enum_key_to_value(const char *key, EnumCharMap *map);

const char * enum_value_to_key(int value, EnumCharMap *map);

#ifdef __cplusplus
}
#endif

#endif
