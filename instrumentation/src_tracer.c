#include "src_tracer.h"
#include "src_tracer_ghost.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

struct _trace_ctx _trace = {
    .ptr = NULL,
    ._page_ptr = NULL,
    .fd = 0,
    .fork_count = 0,
    .try_count = 0,
    .active = 0,
};

static struct _trace_ctx temp_trace;
static int temp_trace_if_reg;

static char trace_fname[200];

void _trace_open(const char *fname) {
    if (_trace.fd > 0) {
        // already opened
        return;
    }
    // Make the file name time dependent
    char timed_fname[160];
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
        return;
    }
    strftime(timed_fname, 160, fname, gmtime(&now.tv_sec));
    snprintf(trace_fname, 170, timed_fname, now.tv_nsec);
    //printf("Trace to: %s\n", trace_fname);

    int lowfd = open(trace_fname, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);

    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd number
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    int fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);

    if(ftruncate(fd, 1l << 36) < 0) {
        perror("ftruncate");
        return;
    }
    // reserve memory for the trace buffer
    _trace._page_ptr = mmap(NULL, 1l << 36, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (_trace._page_ptr == MAP_FAILED) {
        _trace._page_ptr = NULL;
        perror("mmap");
        return;
    }
    if (madvise(_trace._page_ptr, 1l << 36, MADV_SEQUENTIAL) <  0) {
        perror("madvise");
        return;
    }
    if (madvise(_trace._page_ptr, 1l << 36, MADV_DONTFORK) <  0) {
        perror("madvise 2");
        return;
    }
    // map empty block at the end
    //mmap(_trace._page_ptr + (1l << 38), 4096, PROT_NONE, MAP_FIXED | MAP_ANON, -1, 0);

    atexit(_trace_close);

    // now the tracing can start (guarded by _trace.fd > 0 and _trace.active)
    _trace.fd = fd;
    _trace_if_reg = _TRACE_IF_REG_INIT;
    _trace.ptr = _trace._page_ptr;
    _trace.active = 1;
}

void _trace_before_fork(void) {
    if (_trace.fd <= 0) {
        // tracing has already been aborted!
        return;
    }
    _trace.fork_count += 1;
    _TRACE_NUM(_trace.fork_count);

    // stop tracing
    temp_trace.ptr = _trace.ptr;
    temp_trace.fd = _trace.fd;
    temp_trace.active = _trace.active;
    temp_trace_if_reg = _trace_if_reg;
    _trace.ptr = NULL;
    _trace.fd = 0;
    _trace.active = 0;
    _trace_if_reg = 0;
}

int _trace_after_fork(int pid) {
    if (temp_trace.fd <= 0) {
        // tracing has already been aborted!
        return pid;
    }
    if (pid != 0) {
        // we are in the parent
        // resume tracing
        _trace.ptr = temp_trace.ptr;
        _trace.fd = temp_trace.fd;
        _trace.active = temp_trace.active;
        _trace_if_reg = temp_trace_if_reg;

        _TRACE_NUM(pid < 0 ? -1 : 1);
        return pid;
    }
    // we are in a fork
    close(temp_trace.fd);
    temp_trace.fd = 0;
    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", _trace.fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    int lowfd = open(trace_fname, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    int fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);

    if(ftruncate(fd, 1l << 36) < 0) {
        perror("ftruncate");
        return pid;
    }
    // reserve memory for the trace buffer
    _trace._page_ptr = mmap(NULL, 1l << 36, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (_trace._page_ptr == MAP_FAILED) {
        _trace._page_ptr = NULL;
        perror("mmap");
        return pid;
    }
    if (madvise(_trace._page_ptr, 1l << 36, MADV_SEQUENTIAL) <  0) {
        perror("madvise");
        return pid;
    }
    if (madvise(_trace._page_ptr, 1l << 36, MADV_DONTFORK) <  0) {
        perror("madvise 2");
        return pid;
    }
    // now the tracing can start (guarded by _trace.fd > 0 and _trace.active)
    _trace.ptr = _trace._page_ptr;
    _trace.fd = fd;
    _trace.active = 1;
    _trace_if_reg = _TRACE_IF_REG_INIT;

    _TRACE_NUM(pid);
    return pid;
}

void _trace_close(void) {
    if (_trace.fd <= 0) {
        // already closed or never successfully opened
        return;
    }
    _TRACE_END();
    _TRACE_PUT(_IF_BYTE);
    int fd = _trace.fd;
    ssize_t written = (char*)_trace.ptr - (char*)_trace._page_ptr;

    // stop tracing
    _trace.ptr = NULL;
    _trace.fd = 0;
    _trace.active = 0;
    _trace_if_reg = 0;

    // now we call a library function without being traced
    ftruncate(fd, written);
    munmap(_trace._page_ptr, 1l << 36);
    close(fd);
}


// for retracing

// use volatile to forbid optimizing the variable accesses away

// use barrier() to forbid reordering those functions
#define barrier() __asm__ __volatile__("": : :"memory")


void _retrace_if(void) { barrier(); }
void _retrace_else(void) { barrier(); }

volatile int _retrace_fun_num;
void _retrace_fun_call(void) { barrier(); }
void _retrace_return(void) { barrier(); }

volatile long long int _retrace_int;
void _retrace_wrote_int(void) { barrier(); }

volatile int _retrace_fork_count;

// ghost code
void _retrace_ghost_start(void) { barrier(); }
void _retrace_ghost_end(void) { barrier(); }
// true for combined trace/retrace mode
volatile bool _retrace_in_ghost = true;

char *volatile _retrace_assert_names[ASSERT_BUF_SIZE];
volatile bool  _retrace_asserts[ASSERT_BUF_SIZE];
volatile int   _retrace_assert_idx;
void  _retrace_assert_passed(void) { barrier(); }

char *volatile _retrace_assume_name;
volatile bool  _retrace_assume;
void  _retrace_assume_passed(void) { barrier(); }

void _retrace_prop_start(void) { barrier(); }
volatile bool _retrace_prop_is_assert;
volatile bool _retrace_prop_is_assume;
void _retrace_prop_passed(void) { barrier(); }

char *volatile _retrace_dump_names[GHOST_DUMP_BUF_SIZE];
void *volatile _retrace_dumps[GHOST_DUMP_BUF_SIZE];
volatile int   _retrace_dump_idx;
void  _retrace_dump_passed(void) { barrier(); }

// for both tracing and retracing
volatile bool _is_retrace_mode = false;
