#define _GNU_SOURCE

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

// editable constant definitions
#ifndef WRITE_BLOCK_SIZE
#define WRITE_BLOCK_SIZE 32768
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

static int trace_fd;

__attribute__((noreturn))
static void my_exit(void) {
    close(_trace_uffd);
    close(trace_fd);
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

static void my_write(void *ptr, int len) {
    ssize_t written = write(trace_fd, ptr, len);
    if (unlikely(written != len)) {
        // some write error occured
        // abort trace recording
        my_exit();
    }
}

static void finish_write(char *ptr, int len) {
    // find were the trace ended
    int end = len;
    while (end > 0 && ptr[end-1] != 'E') end--;
    if (end == 0) end = len;
    my_write(ptr, end);
}

void *forked_write (void *trace_fname) {
    trace_fd = open((char*)trace_fname,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY,
                    S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        my_exit();
    }

    char *const ptr = _trace_ptr;
    unsigned short pos = 0;
    unsigned short next_pos = WRITE_BLOCK_SIZE;

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

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            // some other event?
            // should not happen!
            my_exit();
        }

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

        my_write(this_ptr, WRITE_BLOCK_SIZE);

        pos = next_pos;
        next_pos += WRITE_BLOCK_SIZE;
    }
}
