#ifndef __CICFLOWMETER_UTIL_ENUM_H__
#define __CICFLOWMETER_UTIL_ENUM_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MAP_ {
    const char *key;
    int value;
} MAP_T;

int get_map_value(const char *key, MAP_T *map);
const char *get_map_key(int value, MAP_T *map);

#ifdef __cplusplus
}
#endif

#endif
