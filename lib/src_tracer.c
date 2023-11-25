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
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static unsigned char dummy[65536] __attribute__ ((aligned (4096)));
#define TRACE_FD_SIZE_STEP 32768
static unsigned short trace_written_pos;

__attribute__((aligned(4096))) unsigned char *restrict _trace_buf = dummy;
void __attribute__((aligned(4096))) *_trace_ptr = dummy;
unsigned short _trace_pos;
unsigned char _trace_ie_byte = _TRACE_IE_BYTE_INIT;

int *_trace_futex;

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
static pthread_t writer_tid;
#else
static pid_t writer_pid;
#endif

extern
__attribute__((returns_twice))
pid_t my_fork(void);

static void segv_handler(int nr, siginfo_t *si, void *unused) {
    // is it even in the addr range of the trace?
    if (si->si_addr < _trace_ptr || _trace_ptr + 65536 <= si->si_addr) {
        exit(EXIT_FAILURE);
    }

    // inform write process to write on the disk
    int num = trace_written_pos / TRACE_FD_SIZE_STEP;
    _trace_futex[num] = 1;
    syscall(SYS_futex, &_trace_futex[num], FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    // mprotect for future segv handling
    mprotect(_trace_ptr + trace_written_pos, 4096, PROT_NONE);
 
    trace_written_pos += TRACE_FD_SIZE_STEP;
    num = trace_written_pos / TRACE_FD_SIZE_STEP;

    // wait until write process finished current writing
    int val = _trace_futex[num];
    while (val != 0) {
        int ret = syscall(SYS_futex, &_trace_futex[num], FUTEX_WAIT, val, NULL, NULL, 0);
        val = _trace_futex[num];
        if (val != 0 && ret != 0) {
            // timeout? don't care about tracing anymore
            _trace_buf = dummy;
            perror("futex");
            break;
        }
    }

    // resolve current segv with mprotect
    mprotect(_trace_ptr + trace_written_pos, 4096, PROT_WRITE);
}


static void create_trace_process(void) {
    // reserve memory for the trace buffer
    _trace_ptr = mmap(NULL, 65536 + 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (_trace_ptr == MAP_FAILED) {
        _trace_ptr = dummy;
        perror("mmap");
        return;
    }

    _trace_futex = _trace_ptr + 65536;

#ifdef _TRACE_USE_PTHREAD
    pthread_create(&writer_tid, NULL, &forked_write, trace_fname);
#else
    // block SIGPOLL (for child)
    //sigset_t sigset, oldset;
    //sigemptyset(&sigset);
    //sigaddset(&sigset, SIGPOLL);
    //sigprocmask(SIG_BLOCK, &sigset, &oldset);

    // bsd style daemon + close all fd
    if ((writer_pid = my_fork()) == 0) {
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

    // unblock SIGPOLL only in parent
    //sigprocmask(SIG_SETMASK, &oldset, NULL);
#endif

    // segv interrupt
    // when reaching the mprotect area, segv handler calls writes
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
        return;
    }

    // mprotect to generate the segv
    for (unsigned short i = TRACE_FD_SIZE_STEP; i != 0; i += TRACE_FD_SIZE_STEP) {
        if (mprotect(_trace_ptr + i, 4096, PROT_NONE)) {
            perror("mprotect");
            return;
        }
    }
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
    // stop tracing
    _TRACE_END();
    trace_written_pos += TRACE_FD_SIZE_STEP;

    // trace end marker -1
    int num = trace_written_pos / TRACE_FD_SIZE_STEP;
    _trace_futex[num] = -1;
    syscall(SYS_futex, &_trace_futex[num], FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    // now we can safely call library functions
    munmap(_trace_ptr, 65536);
    _trace_ptr = dummy;
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
