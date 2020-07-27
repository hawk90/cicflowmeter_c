#include <stddef.h>
#include <strings.h>

#include "enum.h"
#include "debug.h"

int enum_key_to_value(const char *key, EnumCharMap *map)
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


const char *enum_value_to_key(int value, EnumCharMap *map)
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
