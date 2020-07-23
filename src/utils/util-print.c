#include "../common/cicflowmeter-common.h"
#include "util-print.h"
#include "util-error.h"
#include "util-debug.h"
#include <stdio.h>
#include <stdarg.h>		// __VA_ARGS__
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#define BUFFER_LENGTH 2048


#define print_buffer_data(buffer, buffer_offset_ptr, buffer_size, ...) do {		\
		int rc = 0;																\
		rc = snprintf((buffer) + *(buffer_offset_ptr),							\
						  (buffer_size) - *(buffer_offset_ptr),					\
						  __VA_ARGS__);											\
		if(rc >= 0) {															\
			if((*(buffer_offset_ptr) + rc) >= buffer_size) {					\
				*(buffer_offset_ptr) = buffer_size - 1;							\
			} else {															\
				*(buffer_offset_ptr) += rc;										\
			}																	\
		} 																		\
	} while(0)											


/**
* :brief print a buffer as hex
*
* Prints in the format "00 AA BB"
*
* :param wirrten_buffer	- buffer into which the output is written
* :param offset			- where to start writting into the buffer
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rc
**/
int print_buffer_raw_line_hex(char *nbuffer, int *offset, int max_size, const uint8_t *buffer, uint32_t buffer_length)
{
	uint32_t i = 0;

	for(i = 0; i < buffer_length; i++) {
		print_buffer_data(nbuffer, offset, max_size, "%02X ", buffer[i]);
	}

	return 0;
}


/**
* :brief print a buffer as hex
*
* Prints in the format "00 AA BB"
*
* :param wirrten_buffer	- buffer into which the output is written
* :param offset			- where to start writting into the buffer
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rc
**/
int print_raw_uri_fp(FILE *fp, uint8_t *buffer, uint32_t buffer_length)
{
	char nbuffer[BUFFER_LENGTH] = "";
	uint32_t offset = 0;
	uint32_t i = 0;
	int rc = 0;

	for(i = 0; i < buffer_length; i++) {
		if(isprint(buffer[i]) && buffer[i] != '\"') {
			if(buffer[i] == '\\') {
				print_buffer_data(nbuffer, &offset, BUFFER_LENGTH, "\\\\");
			} else {
				print_buffer_data(nbuffer, &offset, BUFFER_LENGTH, "%c", buffer[i]);
			}
		} else {
			print_buffer_data(nbuffer, &offset, BUFFER_LENGTH, "\\x%02X", buffer[i]);
		}
	}
	
	rc = fprintf(fp, "%s", nbuffer);
	if(rc < 0) {
		goto error;
	}

	return 0;

error:
	return -1;
}
