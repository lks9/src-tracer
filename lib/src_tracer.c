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
#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <pthread.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static unsigned char dummy[65536] __attribute__ ((aligned (4096)));
static int trace_fd;
#define TRACE_FD_SIZE_STEP 4096
static off_t trace_fd_size;
static unsigned short trace_mapped_pos;

__attribute__((aligned(4096))) unsigned char *restrict _trace_buf = dummy;
void __attribute__((aligned(4096))) *_trace_ptr = dummy;
unsigned short _trace_pos;
unsigned char _trace_ie_byte = _TRACE_IE_BYTE_INIT;

static __attribute__((aligned(4096))) void *temp_trace_buf = dummy;
static unsigned short temp_trace_pos;
static unsigned char temp_trace_ie_byte = _TRACE_IE_BYTE_INIT;

struct _trace_ctx _trace = {
    .fork_count = 0,
    .try_count = 0,
};

static char trace_fname[200];

extern void *forked_write(char *);
#ifdef _TRACE_USE_PTHREAD
static pthread_t thread_id;
#endif

extern
__attribute__((returns_twice))
pid_t my_fork(void);

static void sigbus_handler(int nr) {
    // sync what was already written
    short old_mapped_pos = trace_mapped_pos - TRACE_FD_SIZE_STEP;
    msync(&_trace_buf[old_mapped_pos], TRACE_FD_SIZE_STEP, MS_ASYNC);

    // resulve sigbus with ftruncate
    trace_fd_size += TRACE_FD_SIZE_STEP;
    ftruncate(trace_fd, trace_fd_size);

    // map the next memory range (writing there will produce sigbus, to be handled again)
    trace_mapped_pos += TRACE_FD_SIZE_STEP;
    mmap(&_trace_buf[trace_mapped_pos], TRACE_FD_SIZE_STEP, PROT_READ | PROT_WRITE,
         MAP_FIXED | MAP_SHARED, trace_fd, trace_fd_size);
}

static void create_trace_process(void) {
    int lowfd = open(trace_fname, O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    if (lowfd < 0) {
        perror("open");
        return;
    }
    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd number
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    trace_fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);

    trace_fd_size = TRACE_FD_SIZE_STEP;
    if(ftruncate(trace_fd, trace_fd_size) < 0) {
        perror("ftruncate");
        close(trace_fd);
        return;
    }

    // reserve memory address range for the trace buffer
    _trace_ptr = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, trace_fd, 0);
    if (_trace_ptr == MAP_FAILED) {
        _trace_ptr = dummy;
        perror("mmap");
        return;
    }

    // when reaching the end of file, sigbus handler calls ftruncate
    signal(SIGBUS, sigbus_handler);
}

void _trace_open(const char *fname) {
    if (_trace_ptr != dummy) {
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

    create_trace_process();

    atexit(_trace_close);

    // now the tracing can start (guarded by _trace_buf != dummy)
    _trace_buf = _trace_ptr;
    _trace_pos = 0;
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;
}

void _trace_before_fork(void) {
    if (_trace_buf == dummy) {
        // tracing has already been aborted!
        return;
    }
    _trace.fork_count += 1;
    _TRACE_NUM(_trace.fork_count);

    temp_trace_buf = _trace_buf;
    temp_trace_pos = _trace_pos;
    temp_trace_ie_byte = _trace_ie_byte;

    // stop tracing
    _trace_buf = dummy;
}

int _trace_after_fork(int pid) {
    if (temp_trace_buf == dummy) {
        // tracing has already been aborted!
        return pid;
    }
    if (pid != 0) {
        // we are in the parent
        // resume tracing
        _trace_buf = temp_trace_buf;
        _trace_pos = temp_trace_pos;
        _trace_ie_byte = temp_trace_ie_byte;

        _TRACE_NUM(pid < 0 ? -1 : 1);
        return pid;
    }
    // we are in a fork

    // just to be sure
    _trace_buf = dummy;
    temp_trace_buf = dummy;

    // unmap old trace buffer
    munmap(_trace_ptr, 65536);
    _trace_ptr = dummy;

    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", _trace.fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    create_trace_process();

    // now the tracing can start (guarded by _trace_ptr != dummy)
    _trace_buf = _trace_ptr;
    _trace_pos = 0;
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;

    _TRACE_NUM(pid);
    return pid;
}

void _trace_close(void) {
    if (_trace_buf == dummy || _trace_ptr == dummy) {
        // already closed, paused or never successfully opened
        return;
    }
    _TRACE_END();
    // stop tracing
    _trace_buf = dummy;

    // now we can safely call library functions
    munmap(_trace_ptr, 65536);
    _trace_ptr = dummy;

    trace_fd_size -= TRACE_FD_SIZE_STEP;
    trace_fd_size += _trace_pos % TRACE_FD_SIZE_STEP;
    ftruncate(trace_fd, trace_fd_size);
    close(trace_fd);
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

long long *volatile _retrace_symbolic[RETRACE_SYMBOLIC_SIZE];
volatile int _retrace_symbolic_idx;

// for both tracing and retracing
volatile bool _is_retrace_mode = false;
