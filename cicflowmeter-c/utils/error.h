#ifndef __CICFLOWMETER_UTILS_ERROR_H__
#define __CICFLOWMETER_UTILS_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	OK,
	EXIT,
	ERROR_SPRINTF,
	ERROR_CODE_MAX
} Error;


const char *error_to_string(Error error_code);
#ifdef __cplusplus
}
#endif

#endif
