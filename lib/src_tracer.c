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

__attribute__((aligned(4096))) unsigned char *restrict _trace_buf = dummy;
void __attribute__((aligned(4096))) *_trace_ptr = dummy;
unsigned short _trace_pos;
unsigned char _trace_ie_byte = _TRACE_IE_BYTE_INIT;

static int trace_fork_count = 0;

unsigned long long int _trace_setjmp_idx;
bool _trace_pointer_call;

static __attribute__((aligned(4096))) void *temp_trace_buf = dummy;
static unsigned short temp_trace_pos;
static unsigned char temp_trace_ie_byte = _TRACE_IE_BYTE_INIT;

static char trace_fname[200];

extern void *forked_write(void *);
#ifdef _TRACE_USE_PTHREAD
static pthread_t thread_id;
#endif

extern
__attribute__((returns_twice))
pid_t my_fork(void);

static void create_trace_process(void) {
    // reserve memory for the trace buffer
    _trace_ptr = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (_trace_ptr == MAP_FAILED) {
        _trace_ptr = dummy;
        perror("mmap");
        return;
    }

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
}

void _trace_open(const char *fname) {
    if (_trace_ptr != dummy) {
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
    trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_FORK, trace_fork_count);

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

        // _TRACE_NUM(pid < 0 ? -1 : 1);
        _TRACE_IF();
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
    snprintf(fname_suffix, 20, "-fork-%d.trace", trace_fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    create_trace_process();

    // now the tracing can start (guarded by _trace_ptr != dummy)
    _trace_buf = _trace_ptr;
    _trace_pos = 0;
    _trace_ie_byte = _TRACE_IE_BYTE_INIT;

    // _TRACE_NUM(pid);
    _TRACE_ELSE();
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
#ifdef _TRACE_USE_PTHREAD
    // FIXME
    pthread_join(thread_id, NULL);
#endif
    munmap(_trace_ptr, 65536);
    _trace_ptr = dummy;
}


// for retracing

// use volatile to forbid optimizing the variable accesses away

// use barrier() to forbid reordering those functions
#define barrier() __asm__ __volatile__("": : :"memory")


volatile char _retrace_letter;
volatile long long int _retrace_num;
void _retrace_breakpoint(void) { barrier(); }

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
