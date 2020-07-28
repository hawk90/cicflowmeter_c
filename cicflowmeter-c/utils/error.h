#ifndef __CICFLOWMETER_UTILS_ERROR_H__
#define __CICFLOWMETER_UTILS_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	ERROR_NONE = -1,
	OK = 0,
	/* warning */
		/* */
		/* */

	/* error */
		/* */
		/* */
	ERROR_EXIT,
	ERROR_SPRINTF,

	/* error max */
	ERROR_CODE_MAX
} ERROR_CODE;


const char *error_to_string(ERROR_CODE error_code);
#ifdef __cplusplus
}
#endif

#endif
