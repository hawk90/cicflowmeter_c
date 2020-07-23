#include "../common/cicflowmeter-common.h"
#include "util-print.h"
#include "util-error.h"
#include "util-debug.h"
#include <stdio.h>
#include <stdarg.h>		// __VA_ARGS__
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/socket.h>

#define BUFFER_LENGTH 2048

#define print_buffer_data(buffer, buffer_offset_ptr, buffer_size, ...) do {		\
		int rt = 0;																\
		rt = snprintf((buffer) + *(buffer_offset_ptr),							\
						  (buffer_size) - *(buffer_offset_ptr),					\
						  __VA_ARGS__);											\
		if(rt >= 0) {															\
			if((*(buffer_offset_ptr) + rt) >= buffer_size) {					\
				*(buffer_offset_ptr) = buffer_size - 1;							\
			} else {															\
				*(buffer_offset_ptr) += rt;										\
			}																	\
		} 																		\
	} while(0)											

/**
* :brief print a buffer as hex
*
* Prints in the format "00 AA BB"
*
* :param nbuffer	- buffer into which the output is written
* :param offset			- where to start writting into the buffer
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rt
**/
int print_buffer_data_modify()
{

	return 0;
}

/**
* :brief print a buffer as hex
*
* Prints in the format "00 AA BB"
*
* :param nbuffer	- buffer into which the output is written
* :param offset			- where to start writting into the buffer
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rt
**/
int print_buffer_raw_line_hex(char *nbuffer, uint32_t *offset, const uint32_t nbuffer_length, const uint8_t *buffer, const uint32_t buffer_length) 
{
	uint32_t idx = 0;

	for(idx = 0; idx < buffer_length; idx++) {
		print_buffer_data(nbuffer, offset, nbuffer_length, "%02X ", buffer[idx]);
	}

	return 0;
}


/**
* :brief ~~
*
* Ex.
*
* :param nbuffer		- buffer into which the output is written
* :param offset			- where to start writting into the buffer
* :param nbuffer_length	- length of the output buffer
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rt
**/
int print_raw_uri_buffer(char *nbuffer, uint32_t *offset, const uint32_t nbuffer_length, const uint8_t *buffer, const uint32_t buffer_length)
{
	uint32_t idx = 0;

	for(idx = 0; idx < buffer_length; idx++) {
		if(isprint(buffer[idx]) && buffer[idx] != '\"') {
			if(buffer[idx] == '\\') {
				print_buffer_data(nbuffer, offset, nbuffer_length, "\\\\");
			} else {
				print_buffer_data(nbuffer, offset, nbuffer_length, "%c", buffer[idx]);
			}
		} else {
			print_buffer_data(nbuffer, offset, nbuffer_length, "\\x%02X", buffer[idx]);
		}
	}

	return 0;
}


/**
* :brief
*
* ~~~~~
*
* :param fp				- 
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rt
**/
int print_raw_uri_fp(FILE *fp, const uint8_t *buffer, const uint32_t buffer_length)
{
	char nbuffer[BUFFER_LENGTH] = "";
	uint32_t offset = 0;
	int rt = 0;

	print_raw_uri_buffer(nbuffer, &offset, BUFFER_LENGTH, (char *)buffer, buffer_length);
	
	rt = fprintf(fp, "%s", nbuffer);
	if(rt < 0) {
		goto error;
	}

	return 0;

error:
	return -1;
}


/**
* :brief
*
* ~~~~~
*
* :param fp				- 
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rt
**/
int print_raw_data_to_buffer(uint8_t *nbuffer, uint32_t *offset, const uint32_t nbuffer_length, const uint8_t *buffer, const uint32_t buffer_length)
{
	int ch = 0;
	uint32_t idx = 0;	

	for(idx = 0; idx < buffer_length; idx += 16) {
		print_buffer_data((char *)nbuffer, offset, nbuffer_length, " %04X  ", idx);
		
		for(ch = 0; (idx + ch) < buffer_length && ch < 16; ch++) {
			print_buffer_data((char *)nbuffer, offset, nbuffer_length, " %02X  ", (uint8_t)buffer[idx+ch]);
			if(ch ==7) {
				print_buffer_data((char *)nbuffer, offset, nbuffer_length, " ");
			}
		}
		if(ch == 16) {
			print_buffer_data((char *)nbuffer, offset, nbuffer_length, " ");
		} else if(ch < 8) {
			int spaces = (16 - ch) * 3 + 2 + 1;
			int idx_space = 0;

			for(idx_space = 0; idx_space < spaces; idx_space++) {
				print_buffer_data((char *)nbuffer, offset, nbuffer_length, " ");
			}

		} else if(ch < 16) {
			int spaces = (16 - ch) * 3 + 2;
			int idx_space = 0;

			for(idx_space = 0; idx_space < spaces; idx_space++) {
				print_buffer_data((char *)nbuffer, offset, nbuffer_length, " ");
			}
		}

		for(ch = 0; (idx + ch) < buffer_length && ch < 16; ch++) {
			print_buffer_data((char *)nbuffer, offset, nbuffer_length, "%c", isprint((uint32_t)buffer[idx+ch]) ? (uint8_t)buffer[idx+ch] : '.');

			if(ch == 7)
				print_buffer_data((char *)nbuffer, offset, nbuffer_length, " ");
			if(ch == 15)
				print_buffer_data((char *)nbuffer, offset, nbuffer_length, "\n");
		}
	}
	if(ch != 16)
		print_buffer_data((char *)nbuffer, offset, nbuffer_length, "\n");

	return 0;
}

/**
* print_raw_data_to_buffer VS hdump
*/
int hdump(char *tag, char *ptr, int len)
{
	int i, j;
	int chunk = 16;

	for(i = 0; i < len; i++) {
		if(i % chunk == 0) {
			j = i;
			printf("%8d | ", i);
		}

		printf("%02x ", ((char *)ptr)[i]);
	}

	return 0;
}


/**
* :brief
*
* ~~~~~
*
* :param fp				- 
* :param buffer 		- to print from
* :param buffer_length	- length of the input buffer
*
* :return rt
**/
const char *print_inet(int af, const void *src, const void *dst, socklen_t sock_size) 
{
	char *log_msg = NULL;
	switch(af) {
		case AF_INET:
			log_msg = inet_ntop(af, src, dst, sock_size);
			return log_msg;
		case AF_INET6:
			return log_msg;
		default:
			log_msg = "SC_ERR_INVALID_VALUE";												// TODO: make error log fmt
			return log_msg;
	}

	return NULL;
}
