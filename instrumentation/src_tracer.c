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
#include <string.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

unsigned char _trace_if_byte = _TRACE_SET_IE;
int _trace_if_count = 0;
unsigned char _trace_buf[TRACE_BUF_SIZE];
int _trace_buf_pos = 0;

static int trace_fd = 0;
static char trace_fname[160];

static int trace_fork_count = 0;
static unsigned char temp_trace_buf[TRACE_BUF_SIZE];
static int temp_trace_buf_pos;
static unsigned char temp_trace_if_byte;
static int temp_trace_if_count;
static int temp_trace_fd;

#ifndef _TRACE_USE_POSIX_WRITE
// taken from musl (arch/x86_64/syscall_arch.h)
static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
	return ret;
}
#define SYS_write				1
// end musl code
#endif

void _trace_write(const void *buf) {
    if (trace_fd <= 0) return;
#ifdef _TRACE_USE_POSIX_WRITE
    ssize_t written = write(trace_fd, buf, TRACE_BUF_SIZE);
#else
    // Use __syscall3 to avoid recursive calls
    long written = __syscall3(SYS_write, (long)trace_fd, (long)buf, (long)TRACE_BUF_SIZE);
#endif
    if (likely(written == TRACE_BUF_SIZE)) {
        return;
    }
    // some write error occured
    // abort trace recording
    int fd = trace_fd;
    trace_fd = 0;
    close(fd);
    return;
}

#ifndef EFFICIENT_TEXT_TRACE
void _trace_write_text(const void *buf, unsigned long count) {
    if (trace_fd <= 0) return;
#ifdef _TRACE_USE_POSIX_WRITE
    ssize_t written = write(trace_fd, buf, count);
#else
    // Use __syscall3 to avoid recursive calls
    long written = __syscall3(SYS_write, (long)trace_fd, (long)buf, (long)count);
#endif
    if (likely(written == count)) {
        return;
    }
    // some write error occured
    // abort trace recording
    int fd = trace_fd;
    trace_fd = 0;
    close(fd);
    return;
}
#endif

static void trace_write_rest(void) {
    if (trace_fd <= 0) return;
#ifdef _TRACE_USE_POSIX_WRITE
    write(trace_fd, _trace_buf, _trace_buf_pos);
#else
    // Use __syscall3 to avoid recursive calls
    __syscall3(SYS_write, (long)trace_fd, (long)_trace_buf, (long)_trace_buf_pos);
#endif
    // don't care about write errors anymore, will be closed soon!
}

void _trace_open(const char *fname) {
    if (trace_fd > 0) {
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

    int lowfd = open(trace_fname, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);

    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd number
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    int fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);

    atexit(_trace_close);

    // now the tracing can start (guarded by trace_fd > 0)
    trace_fd = fd;
    _trace_buf_pos = 0;
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
}

void _trace_before_fork(void) {
    if (trace_fd <= 0) {
        // tracing has already been aborted!
        return;
    }
    trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_DATA, trace_fork_count);

    // stop tracing
    for (int k = 0; k < TRACE_BUF_SIZE; k++) {
        temp_trace_buf[k] = _trace_buf[k];
    }
    temp_trace_buf_pos = _trace_buf_pos;
    temp_trace_fd = trace_fd;
    temp_trace_if_byte = _trace_if_byte;
    temp_trace_if_count = _trace_if_count;
    trace_fd = 0;
    _trace_buf_pos = 0;
}

int _trace_after_fork(int pid) {
    if (temp_trace_fd <= 0) {
        // tracing has already been aborted!
        return pid;
    }
    if (pid != 0) {
        // we are in the parent
        // resume tracing
        for (int k = 0; i < TRACE_BUF_SIZE; k++) {
            _trace_buf[k] = temp_trace_buf[k];
        }
        _trace_buf_pos = temp_trace_buf_pos;
        _trace_if_byte = temp_trace_if_byte;
        _trace_if_count = temp_trace_if_count;
        trace_fd = temp_trace_fd;
        temp_trace_fd = 0;
        return pid;
    }
    // we are in a fork
    close(temp_trace_fd);
    temp_trace_fd = 0;
    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", trace_fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    int lowfd = open(trace_fname, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    int fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);

    // now the tracing can start (guarded by trace_fd > 0)
    trace_fd = fd;
    _trace_buf_pos = 0;
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
    return pid;
}

void _trace_close(void) {
    if (trace_fd <= 0) {
        // already closed or never successfully opened
        return;
    }
    if (_trace_if_count != 0) {
        _TRACE_NUM(_TRACE_SET_FUNC, 0);
        _TRACE_PUT(_trace_if_byte);
    }
    if (_trace_buf_pos != 0) {
        trace_write_rest();
    }
    // stop tracing
    int fd = trace_fd;
    trace_fd = 0;
    _trace_buf_pos = 0;
    // now we call a library function without being traced
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
