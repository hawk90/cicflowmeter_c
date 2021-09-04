#include "common/cicflowmeter_common.h"

#include "utils/print.h"

void dump_hex_line(char *nbuf, uint32_t *offset_ptr, const uint32_t nbuf_size,
                   const char *buf, uint32_t buf_size) {
    uint32_t idx = 0;

    for (idx = 0; idx < buf_size; idx++) {
        DUMP(nbuf, offset_ptr, nbuf_size, "%02X ", buf[idx]);
    }
}

void dump_hex_pretty(char *nbuf, uint32_t *offset_ptr, const uint32_t nbuf_size,
                     const char *buf, const uint32_t buf_size) {
    int ch = 0;
    uint32_t i = 0;

    for (i = 0; i < buf_size; i += 16) {
        DUMP(nbuf, offset_ptr, nbuf_size, " %04X  ", i);

        for (ch = 0; (i + ch) < buf_size && ch < 16; ch++) {
            DUMP(nbuf, offset_ptr, nbuf_size, "%02X ", buf[i + ch]);
            if (ch == 7) {
                DUMP((char *)nbuf, offset_ptr, nbuf_size, " ");
            }
        }

        if (ch == 16) {
            DUMP((char *)nbuf, offset_ptr, nbuf_size, "  ");
        } else if (ch < 8) {
            int spaces = (16 - ch) * 3 + 2 + 1;
            int s = 0;
            for (; s < spaces; s++) DUMP(nbuf, offset_ptr, nbuf_size, " ");
        } else if (ch < 16) {
            int spaces = (16 - ch) * 3 + 2;
            int s = 0;
            for (; s < spaces; s++) DUMP(nbuf, offset_ptr, nbuf_size, " ");
        }

        for (ch = 0; (i + ch) < buf_size && ch < 16; ch++) {
            DUMP(nbuf, offset_ptr, nbuf_size, "%c",
                 isprint((uint8_t)buf[i + ch]) ? (uint8_t)buf[i + ch] : '.');

            if (ch == 7) DUMP(nbuf, offset_ptr, nbuf_size, " ");
            if (ch == 15) DUMP(nbuf, offset_ptr, nbuf_size, "\n");
        }
    }
    if (ch != 16) DUMP(nbuf, offset_ptr, nbuf_size, "\n");

    return;
}

void dump_uri(char *nbuf, uint32_t *offset_ptr, const uint32_t nbuf_size,
              const char *buf, const uint32_t buf_size) {
    uint32_t i = 0;

    for (i = 0; i < buf_size; i++) {
        if (isprint(buf[i]) && buf[i] != '\"') {
            if (buf[i] == '\\') {
                DUMP(nbuf, offset_ptr, nbuf_size, "\\\\");
            } else {
                DUMP(nbuf, offset_ptr, nbuf_size, "%c", buf[i]);
            }
        } else {
            DUMP(nbuf, offset_ptr, nbuf_size, "\\x%02X", buf[i]);
        }
    }

    return;
}

void dump_string(char *nbuf, uint32_t *offset_ptr, const uint32_t nbuf_size,
                 const char *buf, const uint32_t buf_size) {
    uint32_t ch = 0;

    for (ch = 0; ch < buf_size; ch++) {
        DUMP(nbuf, offset_ptr, nbuf_size, "%c",
             (isprint((uint8_t)buf[ch]) || buf[ch] == '\n' || buf[ch] == '\r')
                 ? (uint8_t)buf[ch]
                 : '.');
    }
    nbuf[nbuf_size - 1] = 0;

    /*
uint32_t ch = 0;
for (ch = 0; ch < buf_size; ch++) {
    DUMP((nbuf, offset_ptr, buf_size, "%c", (isprint(buf[ch]) || buf[ch] == '\n'
|| buf[ch] == '\r') ? buf[ch] : '.');
}
nbuf[nbuf_size - 1] = 0;
    */

    return;
}

const char *dump_inet(const int af, const void *src, char *dst,
                      socklen_t size) {
    switch (af) {
        case AF_INET:
            return inet_ntop(af, src, dst, size);
        case AF_INET6:
            /*
return PrintInetIPv6(src, dst, size);
            */
            return NULL;
        default:
            LOG_ERR_MSG(ERROR_INVALID_VALUE, "Unsupported protocol: %d", af);
    }
    return NULL;
}
