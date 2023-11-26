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
#include <string.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>
#include <linux/userfaultfd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <zstd.h>

// editable constant definitions
#ifndef WRITE_BLOCK_SIZE
#define WRITE_BLOCK_SIZE 32768
#endif
#ifndef COMPRESSION_LEVEL
#define COMPRESSION_LEVEL 3
#endif

// somehow missing in the headers on my system
#ifndef UFFDIO_WRITEPROTECT
struct uffdio_writeprotect {
    struct uffdio_range range; /* Range to change write permission*/
    __u64 mode;                /* Mode to change write permission */
};
#define _UFFDIO_WRITEPROTECT  (0x06)
#define UFFDIO_WRITEPROTECT   _IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, \
                                    struct uffdio_writeprotect)
#define UFFDIO_WRITEPROTECT_MODE_WP		((__u64)1<<0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE	((__u64)1<<1)
#endif

// other macros
#define EXIT_WHEN(cond) \
    if (cond) { \
        my_exit(); \
    }

#define CHECK_ZSTD(fn) \
    EXIT_WHEN(ZSTD_isError(fn))

static int trace_fd;

static char buffIn[ZSTD_BLOCKSIZE_MAX];
static ZSTD_inBuffer input = { buffIn, 0, 0 };
static char buffOut[ZSTD_BLOCKSIZE_MAX];
static ZSTD_outBuffer output = { buffOut, ZSTD_BLOCKSIZE_MAX, 0 };
static ZSTD_CCtx* cctx;

__attribute__((noreturn))
static void my_exit(void) {
    close(_trace_uffd);
    close(trace_fd);
    ZSTD_freeCCtx(cctx);
#ifdef _TRACE_USE_PTHREAD
    pthread_exit((void *)0);
#else
    exit(0);
#endif
}

// side effect free fork version
// without calling atfork etc.
__attribute__((returns_twice))
pid_t my_fork(void) {
    return (pid_t)syscall(SYS_fork);
}

// write and compress
static void my_write(void *ptr, int len, bool last) {
    memcpy(&buffIn[input.pos], ptr, len);

    input.size += len;
    last = last || input.size == ZSTD_BLOCKSIZE_MAX;
    ZSTD_EndDirective const mode = last ? ZSTD_e_end : ZSTD_e_continue;

    CHECK_ZSTD(ZSTD_compressStream2(cctx, &output, &input, mode));
    if (last) {
        ssize_t written = write(trace_fd, buffOut, output.pos);
        // abort trace recording when write error
        EXIT_WHEN(written != output.pos);

        input.pos = 0;
        input.size = 0;
        output.pos = 0;
    }
}

static void finish_write(char *ptr, int len) {
    // find were the trace ended
    int end = len;
    while (end > 0 && ptr[end-1] != 'E') end--;
    if (end == 0) end = len;
    my_write(ptr, end, true);
}

void *forked_write (void *trace_fname) {
    char fname_zstd[200];
    strncat(fname_zstd, (char*)trace_fname, 195);
    strncat(fname_zstd, ".zst", 5);
    trace_fd = open(fname_zstd,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY,
                    S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        my_exit();
    }

    char *const ptr = _trace_ptr;
    unsigned short pos = 0;
    unsigned short next_pos = WRITE_BLOCK_SIZE;

    // initialize zstd compression
    cctx = ZSTD_createCCtx();
    EXIT_WHEN(cctx == NULL);
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, COMPRESSION_LEVEL));
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0));

    while (true) {
        char *this_ptr = &(ptr[pos]);

        // wait until trace producer finished current segment
        struct uffd_msg msg;
        if (read(_trace_uffd, &msg, sizeof(struct uffd_msg)) != sizeof(struct uffd_msg)) {
            // should not happen!
            my_exit();
        }

        if (msg.event == UFFD_EVENT_UNMAP) {
            // tracing finished
            finish_write(this_ptr, WRITE_BLOCK_SIZE);
            my_exit();
        }

        // some other event?
        // should not happen!
        EXIT_WHEN(msg.event != UFFD_EVENT_PAGEFAULT);

        // insert the trap for the next page fault
        {
            struct uffdio_writeprotect wp2;
            wp2.range.start = (unsigned long)_trace_ptr + pos;
            wp2.range.len = 4096;
            wp2.mode = UFFDIO_WRITEPROTECT_MODE_WP;
            ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp2);
        }

        // resolve current page fault
        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
            // page is there, but write protected
            struct uffdio_writeprotect wp1;
            wp1.range.start = (unsigned long)_trace_ptr + next_pos;
            wp1.range.len = 4096;
            wp1.mode = 0;
            ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp1);
        } else {
            // page is missing
            struct uffdio_zeropage zp;
            zp.range.start = (unsigned long)_trace_ptr + next_pos;
            zp.range.len = 4096;
            zp.mode = 0;
            ioctl(_trace_uffd, UFFDIO_ZEROPAGE, &zp);
        }

        my_write(this_ptr, WRITE_BLOCK_SIZE, false);

        pos = next_pos;
        next_pos += WRITE_BLOCK_SIZE;
    }
}
