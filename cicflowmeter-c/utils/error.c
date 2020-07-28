#include "error.h"

#define ERROR_CASE(E) case E: return #E

const char *error_to_string(ERROR_CODE error_code)
{
    switch(error_code) {
        ERROR_CASE (OK);

        /* end */
        ERROR_CASE (ERROR_CODE_MAX);
    }

    return "UNKNOWN_ERROR";
}

