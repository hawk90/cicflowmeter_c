const char *error_to_string(Error error_code)
{
    switch(error_code) {
        ERROR_CASE (OK);

        /* end */
        ERROR_CASE (ERROR_CODE_MAX);
    }

    return "UNKNOWN_ERROR";
}

