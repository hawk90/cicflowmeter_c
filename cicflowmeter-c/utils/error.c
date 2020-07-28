#include "error.h"

#define ERROR_CASE(E) case E: return #E

const char *error_to_string(ERROR_CODE error_code)
{
    switch(error_code) {
		ERROR_CASE (ERROR_NONE);
        ERROR_CASE (OK);

		ERROR_CASE (ERROR_EXIT);
		ERROR_CASE (ERROR_SPRINTF);

        /* error code max */
        ERROR_CASE (ERROR_CODE_MAX);
    }

    return "UNKNOWN_ERROR";
}

