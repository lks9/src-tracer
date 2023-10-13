#include <src_tracer/_after_instrument.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>


#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static int outfd;

static unsigned char *ptr;
static unsigned short last_pos = 0;
static unsigned short pos = 0;

static inline void __attribute__((always_inline)) put_out(void) {
    pos++;
    if ((unsigned short)(last_pos + 4096) == pos) {
        if(write(outfd, &ptr[last_pos], 4096) == 0) {
            close(outfd);
            pthread_exit(-1);
        }
        // remove unneeded memory
        madvise(&ptr[last_pos], 4096, MADV_REMOVE);
        last_pos = pos;
    }
}

void *forked_write (char *filename) {
    outfd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    if (outfd <= 0)
        pthread_exit(-1);

    ptr = _trace._page_ptr;

    while (true) {
        unsigned char b;
        for (int timeout = 100; unlikely((b=ptr[pos]) == 0); timeout --) {
            usleep(1000);
            if (timeout == 0) {
                if (write(outfd, &ptr[last_pos], pos - last_pos) < 0)
                    pthread_exit(-1);
                close(outfd);
                pthread_exit(-1);
            }
        }
        switch(b & _TRACE_TEST_OTHER) {
            case _TRACE_SET_FUNC_4:
                break;
            case _TRACE_SET_ELEM_AO:
                if (b == 'E') {
                    put_out();
                    if (write(outfd, &ptr[last_pos], pos - last_pos) == pos - last_pos) {
                        close(outfd);
                        pthread_exit(0);
                    } else {
                        close(outfd);
                        pthread_exit(-1);
                    }
                }
                break;
            case _TRACE_SET_ELEM_PZ:
                break;
            case _TRACE_SET_FUNC_32:
                put_out();
            case _TRACE_SET_FUNC_28:
                put_out();
            case _TRACE_SET_FUNC_20:
                put_out();
            case _TRACE_SET_FUNC_12:
                put_out();
                break;
            case _TRACE_SET_DATA:
                for (int i = 0; i < (b & _TRACE_TEST_LEN_BYTECOUNT); i++) {
                    put_out();
                }
                break;
            default:
                break;
        }
        put_out();
    }
    pthread_exit(0);
}
