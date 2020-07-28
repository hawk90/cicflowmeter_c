#include <stddef.h>
#include <strings.h>

#include "enum.h"
#include "debug.h"

int get_map_value(const char *key, MAP *map)
{
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
//	LogDebug("Invalid argument(s) passed into SCMapEnumNameToValue");
	return -1;
}


const char *get_map_key(int value, MAP *map)
{
    if (map == NULL) goto error;

    for (; map->key != NULL; map++) {
        if (map->value == value) {
            return map->key;
        }
    }

//    LogDebug("A enum by the value %d doesn't exist in this table", value);
    return NULL;

error:
//	LogDebug("Invalid argument(s) passed into SCMapEnumValueToName");
	return NULL;

}
