#ifndef __CICFLOWMETER_UTILS_PRINT_H__
#define __CICFLOWMETER_UTILS_PRINT_H__

#include "debug.h"

#define DUMP(buffer, buffer_offset_ptr, buffer_size, ...)                     \
    do {                                                                      \
        int cw = snprintf((buffer) + *(buffer_offset_ptr),                    \
                          (buffer_size) - *(buffer_offset_ptr), __VA_ARGS__); \
        if (cw >= 0) {                                                        \
            if ((*(buffer_offset_ptr) + cw) >= buffer_size) {                 \
                LOG_DBG_MSG(                                                  \
                    "Truncating data write since it exceeded buffer "         \
                    "limit of - %" PRIu32 "\n",                               \
                    buffer_size);                                             \
                *(buffer_offset_ptr) = buffer_size - 1;                       \
            } else {                                                          \
                *(buffer_offset_ptr) += cw;                                   \
            }                                                                 \
        }                                                                     \
    } while (0)

#endif
