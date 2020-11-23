#ifndef __CICFLOWMETER_UTILS_ENUM_H__
#define __CICFLOWMETER_UTILS_ENUM_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _MAP_T {
    const char *key;
    int value;
} MAP_T;

int get_map_value(const char *key, MAP_T *map);
const char *get_map_key(int value, MAP_T *map);

#ifdef __cplusplus
}
#endif

#endif
