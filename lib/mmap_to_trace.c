#include <src_tracer/_after_instrument.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>


#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static unsigned char outbuf[4096];
static int outpos = 0;

static char *ptr;
static int outfd;

static inline void __attribute__((always_inline)) put_out(unsigned char c) {
    outbuf[outpos++] = c;
    if (outpos == 4096) {
        if(write(outfd, outbuf, 4096) == 0) {
            close(outfd);
            exit(-1);
        }
        // remove unneeded memory
        while (ptr - (char *)_trace._page_ptr > 4096) {
            madvise(_trace._page_ptr, 4096, MADV_REMOVE);
            _trace._page_ptr += 4096;
        }
        outpos = 0;
    }
}

void *forked_write (char *filename) {
    outfd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    if (outfd <= 0)
        exit(-1);
    ptr = _trace._page_ptr;

    int ie_count = 0;
    unsigned char ie_byte = _TRACE_SET_IE;
    for (; true; ptr++) {
        unsigned char b;
        for (int timeout = 1000; unlikely((b=*ptr) == 0); timeout --) {
            usleep(1000);
            if (timeout == 0) {
                if (write(outfd, outbuf, outpos) < 0)
                    exit(-1);
                close(outfd);
                exit(-1);
            }
        }
        if (b == 'T' || b == 'N') {
            ie_byte |= (b == 'T') << ie_count;
            ie_count += 1;
            if (ie_count == 6) {
                put_out(ie_byte | (1 << 6));
                ie_byte = _TRACE_SET_IE;
                ie_count = 0;
            }
            continue;
        }
        if (ie_count > 0) {
            put_out(ie_byte | 1 << ie_count);
            ie_byte = _TRACE_SET_IE;
            ie_count = 0;
        }
        switch(b & _TRACE_TEST_OTHER) {
            case _TRACE_SET_FUNC_4:
                break;
            case _TRACE_SET_ELEM_AO:
                if (b == 'E') {
                    put_out(b);
                    if (write(outfd, outbuf, outpos) == outpos) {
                        close(outfd);
                        exit(0);
                    } else {
                        close(outfd);
                        exit(-1);
                    }
                }
                break;
            case _TRACE_SET_ELEM_PZ:
                break;
            case _TRACE_SET_FUNC_32:
                put_out(*ptr);
                ptr++;
            case _TRACE_SET_FUNC_28:
                put_out(*ptr);
                ptr++;
            case _TRACE_SET_FUNC_20:
                put_out(*ptr);
                ptr++;
            case _TRACE_SET_FUNC_12:
                put_out(*ptr);
                ptr++;
                b = *ptr;
                break;
            case _TRACE_SET_DATA:
                for (int i = 0; i < (b & _TRACE_TEST_LEN_BYTECOUNT); i++, ptr++) {
                    put_out(*ptr);
                }
                b = *ptr;
                break;
            default:
                break;
        }
        put_out(b);
    }
    exit( 0);
}
