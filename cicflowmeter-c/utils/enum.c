#include "cicflowmeter-c/common/cicflowmeter_common.h"

#include "debug.h"
#include "enum.h"

int get_map_value(const char *key, MAP_T *map) {
    int result = -1;

    if (key == NULL || map == NULL) goto error;

    for (; map->key != NULL; map++) {
        if (strcasecmp(map->key, key) == 0) {
            result = map->value;
            break;
        }
    }

    return result;

error:
    LOG_DBG_MSG("Invalid argument(s) passed into get_map_value");
    return -1;
}

const char *get_map_key(int value, MAP_T *map) {
    if (map == NULL) goto error;

    for (; map->key != NULL; map++) {
        if (map->value == value) {
            return map->key;
        }
    }

    LOG_DBG_MSG("A enum by the value %d doesn't exist in this map", value);
    return NULL;

error:
    LOG_DBG_MSG("Invalid argument(s) passed into get_map_key");
    return NULL;
}
