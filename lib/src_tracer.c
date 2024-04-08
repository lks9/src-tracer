#include <src_tracer/_after_instrument.h>
#include <src_tracer/ghost.h>

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

unsigned char _trace_ie_byte = _TRACE_IE_BYTE_INIT;
unsigned char _trace_buf[TRACE_BUF_SIZE];
int _trace_buf_pos = 0;

static int trace_fd = 0;
static char trace_fname[170];

static int trace_fork_count = 0;
static unsigned char temp_trace_buf[TRACE_BUF_SIZE];
static int temp_trace_buf_pos;
static int temp_trace_fd;

unsigned long long int _trace_setjmp_idx;

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
        _trace_close();
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
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;
}

void _trace_before_fork(void) {
    if (trace_fd <= 0) {
        // tracing has already been aborted!
        return;
    }
    trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_FORK, trace_fork_count);

    // stop tracing
    for (int k = 0; k < TRACE_BUF_SIZE; k++) {
        temp_trace_buf[k] = _trace_buf[k];
    }
    temp_trace_buf_pos = _trace_buf_pos;
    temp_trace_fd = trace_fd;
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
        for (int k = 0; k < TRACE_BUF_SIZE; k++) {
            _trace_buf[k] = temp_trace_buf[k];
        }
        trace_fd = temp_trace_fd;
        temp_trace_fd = 0;
        _trace_buf_pos = temp_trace_buf_pos;
        _trace_ie_byte = _TRACE_IE_BYTE_INIT;

        // _TRACE_NUM(pid < 0 ? -1 : 1);
        _TRACE_IF();
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
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;

    // _TRACE_NUM(pid);
    _TRACE_ELSE();
    return pid;
}

void _trace_close(void) {
    if (trace_fd <= 0) {
        // already closed or never successfully opened
        return;
    }
    _TRACE_END();
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

// use volatile to forbid optimizing the variable accesses away

// use barrier() to forbid reordering those functions
#define barrier() __asm__ __volatile__("": : :"memory")


volatile char _retrace_letter;
volatile long long int _retrace_num;
void _retrace_compare_elem(void) { barrier(); }

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

long long *volatile _retrace_symbolic[RETRACE_SYMBOLIC_SIZE];
volatile int _retrace_symbolic_idx;

// for both tracing and retracing
volatile bool _is_retrace_mode = false;
