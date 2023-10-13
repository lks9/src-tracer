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

static char trace_fname[170];


static unsigned char dummy[65536];

struct _trace_ctx _trace = {
    .ptr = dummy,
    ._page_ptr = NULL,
    .pos = 0,
    .ie_byte = _TRACE_IE_BYTE_INIT,
    .fork_count = 0,
    .try_count = 0,
};

static struct _trace_ctx temp_trace;

extern char **__environ;

extern void *forked_write(char *);
pthread_t thread_id;

void _trace_open(const char *fname) {
    if (_trace._page_ptr != NULL) {
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

    // reserve memory for the trace buffer
    _trace._page_ptr = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (_trace._page_ptr == MAP_FAILED) {
        _trace._page_ptr = NULL;
        perror("mmap");
        return;
    }
    //if (madvise(_trace._page_ptr, 65536, MADV_SEQUENTIAL) <  0) {
    //    perror("madvise");
    //    return;
    //}
    // map empty block at the end
    //mmap(_trace._page_ptr + (1l << 38), 4096, PROT_NONE, MAP_FIXED | MAP_ANON, -1, 0);

    //char ptr_str[8];
    //snprintf(ptr_str, 8, "%p", _trace._page_ptr);

#if 0
    if (fork() == 0) {
        // child process
        if (prctl(PR_SET_NAME, (unsigned long)"src_tracer") < 0)
            perror("prctl()");        
        forked_write(trace_fname);
        // will never return
    }
#else
    pthread_create(&thread_id, NULL, &forked_write, trace_fname);
#endif

    atexit(_trace_close);

    // now the tracing can start (guarded by _trace._page_ptr != NULL)
    _trace.ptr = _trace._page_ptr;
    _trace.pos = 0;
    _trace.ie_byte = _TRACE_IE_BYTE_INIT;
}

void _trace_before_fork(void) {
    if (_trace.ptr == dummy) {
        // tracing has already been aborted!
        return;
    }
    _trace.fork_count += 1;
    _TRACE_NUM(_trace.fork_count);

    temp_trace.ptr = _trace.ptr;
    temp_trace.pos = _trace.pos;
    temp_trace.ie_byte = _trace.ie_byte;

    // stop tracing
    _trace.ptr = dummy;
}

int _trace_after_fork(int pid) {
    if (temp_trace.ptr == dummy) {
        // tracing has already been aborted!
        return pid;
    }
    if (pid != 0) {
        // we are in the parent
        // resume tracing
        _trace.ptr = temp_trace.ptr;
        _trace.pos = temp_trace.pos;
        _trace.ie_byte = temp_trace.ie_byte;

        _TRACE_NUM(pid < 0 ? -1 : 1);
        return pid;
    }
    // we are in a fork
    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", _trace.fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    // reserve memory for the trace buffer
    //munmap(_trace._page_ptr, 1l << 36);
    //_trace._page_ptr = mmap(NULL, 1l << 36, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (_trace._page_ptr == MAP_FAILED) {
        _trace._page_ptr = NULL;
        perror("mmap");
        return pid;
    }
    if (madvise(_trace._page_ptr, 1l << 36, MADV_SEQUENTIAL) <  0) {
        _trace._page_ptr = NULL;
        perror("madvise");
        return pid;
    }
    // now the tracing can start (guarded by _trace._page_ptr != NULL)
    _trace.ptr = _trace._page_ptr;
    _trace.pos = 0;
    _trace.ie_byte = _TRACE_IE_BYTE_INIT;

    //int lowfd = open(trace_fname, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    //int fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    //close(lowfd);

    _TRACE_NUM(pid);
    return pid;
}

void _trace_close(void) {
    if (_trace._page_ptr == NULL) {
        // already closed or never successfully opened
        return;
    }
    _TRACE_END();
#if 1
    pthread_join(thread_id, NULL);
#endif
    // stop tracing
    _trace.ptr = dummy;
    _trace._page_ptr = NULL;
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
