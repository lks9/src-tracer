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

int _trace_fd = 0;

unsigned char _trace_if_byte = _TRACE_SET_IE;
int _trace_if_count = 0;

static char dummy;
char *_trace_ptr = &dummy;
bool _trace_ptr_count = 0;
static void *trace_page_ptr;

static char *temp_trace_ptr;
static unsigned char temp_trace_if_byte;
static int temp_trace_if_count;
static int temp_trace_fd;

static int trace_fork_count = 0;
static char trace_fname[200];

void _trace_open(const char *fname) {
    if (_trace_fd > 0) {
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
    //dprintf(2, "Trace to: %s\n", trace_fname);

    int lowfd = open(trace_fname, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE | O_CLOEXEC, S_IRUSR | S_IWUSR);

    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd number
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    int fd = dup2(lowfd, lowfd + 42);
    close(lowfd);

    if(ftruncate(fd, 1l << 36) < 0) {
        perror("ftruncate");
        return;
    }
    // reserve memory for the trace buffer
    trace_page_ptr = mmap(NULL, 1l << 36, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (trace_page_ptr == MAP_FAILED) {
        trace_page_ptr = NULL;
        perror("mmap");
        return;
    }
    if (madvise(trace_page_ptr, 1l << 36, MADV_SEQUENTIAL) <  0) {
        perror("madvise");
        return;
    }
    if (madvise(trace_page_ptr, 1l << 36, MADV_DONTFORK) <  0) {
        perror("madvise 2");
        return;
    }
    // map empty block at the end
    //mmap(trace_page_ptr + (1l << 38), 4096, PROT_NONE, MAP_FIXED | MAP_ANON, -1, 0);

    atexit(_trace_close);

    // now the tracing can start (guarded by _trace_fd > 0)
    _trace_fd = fd;
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
    _trace_ptr = trace_page_ptr;
    _trace_ptr_count = 1;
}

void _trace_before_fork(void) {
    trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_DATA, trace_fork_count);

    // stop tracing
    temp_trace_ptr = _trace_ptr;
    temp_trace_if_byte = _trace_if_byte;
    temp_trace_if_count = _trace_if_count;
    temp_trace_fd = _trace_fd;
    _trace_ptr = &dummy;
    _trace_ptr_count = 0;
    _trace_fd = 0;
}

void _trace_after_fork(int i) {
    if (i < 0) {
        return;
    } else if (i > 0) {
        // resume tracing
        _trace_ptr = temp_trace_ptr;
        _trace_if_byte = temp_trace_if_byte;
        _trace_if_count = temp_trace_if_count;
        _trace_ptr_count = 1;
        _trace_fd = temp_trace_fd;
        return;
    }
    temp_trace_ptr = &dummy;
    temp_trace_fd = 0;
    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", trace_fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //dprintf(2, "Trace to: %s\n", trace_fname);

    int lowfd = open(trace_fname, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE | O_CLOEXEC, S_IRUSR | S_IWUSR);
    int fd = dup2(lowfd, lowfd + 42);
    close(lowfd);

    if(ftruncate(fd, 1l << 36) < 0) {
        perror("ftruncate");
        return;
    }
    // reserve memory for the trace buffer
    trace_page_ptr = mmap(NULL, 1l << 36, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (trace_page_ptr == MAP_FAILED) {
        trace_page_ptr = NULL;
        perror("mmap");
        return;
    }
    if (madvise(trace_page_ptr, 1l << 36, MADV_SEQUENTIAL) <  0) {
        perror("madvise");
        return;
    }
    if (madvise(trace_page_ptr, 1l << 36, MADV_DONTFORK) <  0) {
        perror("madvise 2");
        return;
    }
    // now the tracing can start (guarded by _trace_fd > 0)
    _trace_fd = fd;
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
    _trace_ptr = trace_page_ptr;
    _trace_ptr_count = 1;
}

void _trace_close(void) {
    if (_trace_fd <= 0) {
        // already closed or never successfully opened
        return;
    }
    if (_trace_if_count != 0) {
        _TRACE_NUM(_TRACE_SET_FUNC, 0);
        _TRACE_PUT(_trace_if_byte);
    }
    // stop tracing
    int fd = _trace_fd;
    _trace_fd = 0;
    ssize_t written = (char*)_trace_ptr - (char*)trace_page_ptr;
    _trace_ptr = &dummy;
    _trace_ptr_count = 0;
    // now we call a library function without being traced
    ftruncate(fd, written);
    munmap(trace_page_ptr, 1l << 36);
    close(fd);
}


// for retracing
void _retrace_if(void) {}
void _retrace_else(void) {}

int _retrace_fun_num;
void _retrace_fun_call(void) {}
void _retrace_return(void) {}

long long int _retrace_int;
void _retrace_wrote_int(void) {}

// ghost code
void _retrace_ghost_start(void) {}
void _retrace_ghost_end(void) {}
// true for combined trace/retrace mode
bool _retrace_in_ghost = true;

char *_retrace_assert_names[ASSERT_BUF_SIZE];
bool  _retrace_asserts[ASSERT_BUF_SIZE];
int   _retrace_assert_idx;
void  _retrace_assert_passed(void) {}

char *_retrace_assume_name;
bool  _retrace_assume;
void  _retrace_assume_passed(void) {}

void _retrace_prop_start(void) {}
bool _retrace_prop_is_assert;
bool _retrace_prop_is_assume;
void _retrace_prop_passed(void) {}

char *_retrace_dump_names[GHOST_DUMP_BUF_SIZE];
void *_retrace_dumps[GHOST_DUMP_BUF_SIZE];
int   _retrace_dump_idx;
void  _retrace_dump_passed(void) {}

// for both tracing and retracing
bool _is_retrace_mode = false;
