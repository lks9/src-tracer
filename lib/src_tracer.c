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

static char trace_fname[200];

unsigned char _trace_buf[65536] __attribute__((aligned(65536)));

struct _trace_ctx _trace = {
    .fork_count = 0,
    .try_count = 0,
};
unsigned char _trace_ie_byte = _TRACE_IE_BYTE_INIT;
unsigned short _trace_pos = 0;

static bool trace_active = false;

extern char **__environ;

extern
__attribute__((noreturn))
void *forked_write(char *);
#ifdef _TRACE_USE_PTHREAD
static pthread_t thread_id;
#endif

extern
__attribute__((returns_twice))
pid_t my_fork(void);

static void create_trace_process(void) {
    // write garbage trace at a position it wouldn't matter
    _trace_pos = 2*4096;

    // reserve memory for the trace buffer
    void *tmp_ptr = mmap(_trace_buf, 65536, PROT_READ | PROT_WRITE,
            MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (tmp_ptr == MAP_FAILED) {
        perror("mmap");
        return;
    }
    // the next fork should have the same _trace_buf
    madvise(_trace_buf, 65536, MADV_DOFORK);

#ifdef _TRACE_USE_PTHREAD
    pthread_create(&thread_id, NULL, &forked_write, trace_fname);
#else
    // bsd style daemon + close all fd
    if (my_fork() == 0) {
        // child process
        // new name
        prctl(PR_SET_NAME, (unsigned long)"src_tracer");
        // session leader
        //    -> independ from the previous process session
        //    -> independent from terminal
        setsid();
        // anything might happen to the current directory, be independent
        chdir("/");
        umask(0);
        // close any fd
        for (int i = sysconf(_SC_OPEN_MAX); i >= 0; i--) {
            close(i);
        }

        forked_write(trace_fname);
        // will never return
    }
#endif
    // further forks should not write to the same trace
    madvise(_trace_buf, 65536, MADV_DONTFORK);
}

void _trace_open(const char *fname) {
    if (trace_active) {
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

    // now the tracing can start (guarded by trace_active)
    trace_active = true;
    _trace_pos = 0;
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;
}

void _trace_before_fork(void) {
    _trace.fork_count += 1;
    _TRACE_NUM(_trace.fork_count);
}

int _trace_after_fork(int pid) {
    if (trace_active == false) {
        // we are not tracing
        return pid;
    }
    if (pid != 0) {
        // we are in the parent
        return pid;
    }
    // we are in a fork
    trace_active = false;
    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", _trace.fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    create_trace_process();

    // now the tracing can start (guarded by trace_active)
    trace_active = true;
    _trace_pos = 0;
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;
    return pid;
}

void _trace_close(void) {
    if (trace_active == false) {
        // already closed, paused or never successfully opened
        return;
    }
    // stop tracing
    _TRACE_END();
    trace_active = false;

    // now we can safely call library functions
#ifdef _TRACE_USE_PTHREAD
    // FIXME
    pthread_join(thread_id, NULL);
#endif
    void *tmp_ptr = mmap(_trace_buf, 65536, PROT_READ | PROT_WRITE,
            MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tmp_ptr == MAP_FAILED) {
        perror("mmap close");
        return;
    }
}

__attribute((used))
void _trace_func(unsigned int num) {
    _TRACE_FUNC(num);
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
