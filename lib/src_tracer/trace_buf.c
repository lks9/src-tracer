#include <src_tracer/constants.h>
#include <src_tracer/trace_elem.h>
#include <src_tracer/trace_mode.h>
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
#include <pthread.h>
#include <errno.h>

#ifndef TRACE_USE_POSIX
  #include "syscalls.h"
#endif
#ifdef TRACEFORK_FUTEX
  #include "sync_futex.h"
#endif

#ifdef TRACEFORK_DEBUG
  #define debug(...) fprintf(stderr, __VA_ARGS__)
#else
  #define perror(...) /* nothing here */
  #define debug(...) /* nothing here */
#endif

extern int tracer_create_daemon(char *trace_fname);


#ifdef TRACE_USE_THREAD_LOCAL
  #define MY_THREAD_LOCAL  __thread
#else
  #define MY_THREAD_LOCAL  /* nothing here */
#endif

// trace buffer
#ifdef TRACE_USE_FORK
  static unsigned char dummy[TRACE_BUF_SIZE] __attribute__ ((aligned (4096)));
  void __attribute__((aligned(4096))) *_trace_ptr = dummy;
  __attribute__((aligned(4096))) MY_THREAD_LOCAL unsigned char *_trace_buf = dummy;
#else
  MY_THREAD_LOCAL unsigned char _trace_buf[TRACE_BUF_SIZE];
#endif

// trace position
#ifdef TRACE_USE_RINGBUFFER
  MY_THREAD_LOCAL
  unsigned short _trace_buf_pos = 0;
#else
  MY_THREAD_LOCAL
  int _trace_buf_pos = 0;
#endif

// trace ie byte
#ifndef BYTE_TRACE
  #ifndef TRACE_IE_LOCAL
    #ifndef TRACE_IE_BYTE_REG
      MY_THREAD_LOCAL
      unsigned char _trace_ie_byte = _TRACE_SET_IE_INIT;
    #endif
  #endif
#endif

// trace file name
static __attribute__((unused)) char trace_fname[200] = "";
static __attribute__((unused)) size_t fname_len_wo_suffix;

// trace fd
int _trace_fd;

// userfault fd
#ifdef TRACEFORK_SYNC_UFFD
  int _trace_uffd;
#endif

// temporary stuff
static __attribute__((unused)) unsigned char temp_trace_buf[TRACE_BUF_SIZE];
static __attribute__((unused)) int temp_trace_buf_pos;
static __attribute__((unused)) int temp_trace_fd;

#ifndef TRACE_USE_RINGBUFFER

#define TRACE_IS_OPEN() (temp_trace_fd > 0)
#define TRACE_IS_ACTIVE() (_trace_fd > 0)


#ifdef TRACE_USE_POSIX
  #define my_write(fd, buf, len)  write(fd, buf, len)
#else
  // Use syscall to avoid recursive calls
  #define my_write(fd, buf, len)  syscall_3(SYS_write, (long)fd, (long)buf, (long)len)
#endif

void _trace_write(void) {
    if (!TRACE_IS_ACTIVE()) return;

    if (likely(my_write(_trace_fd, _trace_buf, TRACE_BUF_SIZE) == TRACE_BUF_SIZE)) {
        return;
    }
    // some write error occured
    // abort trace recording
    int fd = _trace_fd;
    _trace_fd = 0;
    close(fd);
    return;
}

void _trace_write_text(const void *buf, unsigned long count) {
    if (!TRACE_IS_ACTIVE()) return;

    if (likely(my_write(_trace_fd, buf, count) == count)) {
        return;
    }
    // some write error occured
    // abort trace recording
    int fd = _trace_fd;
    _trace_fd = 0;
    close(fd);
    return;
}

static void trace_write_rest(void) {
    if (!TRACE_IS_ACTIVE()) return;

    my_write(_trace_fd, _trace_buf, _trace_buf_pos);
    // don't care about write errors anymore, will be closed soon!
}

static void open_trace_fd(void) {
    int lowfd = open(trace_fname, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);

    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    temp_trace_fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);
}

#elif defined TRACE_USE_FORK
// use the ringbuffer and write in a separate fork

#define TRACE_IS_OPEN() (_trace_ptr != dummy)
#define TRACE_IS_ACTIVE() (_trace_buf != dummy)

#ifdef TRACEFORK_FUTEX
  #define MMAP_SIZE  (TRACE_BUF_SIZE + 4096)
#else
  #define MMAP_SIZE  TRACE_BUF_SIZE
#endif

#ifdef TRACEFORK_FUTEX
uint32_t *_trace_pos_futex_var;
void _tracefork_sync(void) {
    if (TRACE_IS_ACTIVE()) {
        *_trace_pos_futex_var = _trace_buf_pos;
        long res = futex_wake(_trace_pos_futex_var);
        if (unlikely(res < 0)) {
            // abort tracing
            _trace_buf = dummy;
#ifdef TRACEFORK_DEBUG
            errno = -res;
            perror("futex_wake");
#endif
        }
    }
}
#endif

static void create_trace_process(void) {
    // reserve shared memory for the trace buffer
    _trace_ptr = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (_trace_ptr == MAP_FAILED) {
        _trace_ptr = dummy;
        perror("mmap");
    }

#ifdef TRACEFORK_FUTEX
    _trace_pos_futex_var = _trace_ptr + TRACE_BUF_SIZE;
#endif

    if (tracer_create_daemon(trace_fname) < 0) {
        munmap(_trace_ptr, MMAP_SIZE);
        _trace_ptr = dummy;
        perror("tracer_create_daemon");
    }
}

#endif // TRACE_USE_FORK

#if !defined TRACE_USE_RINGBUFFER || defined TRACE_USE_FORK

static void trace_open_fname(const char *suffix) {
    fname_len_wo_suffix = strlen(trace_fname);
    strncat(trace_fname, suffix, 15);
    debug("Trace to: %s\n", trace_fname);

#ifndef TRACE_USE_RINGBUFFER
    open_trace_fd();
#elif defined TRACE_USE_FORK
    create_trace_process();
#endif
    if (!TRACE_IS_OPEN()) {
        perror("open trace");
        return;
    }

    atexit(_trace_close);

#ifndef TRACE_USE_RINGBUFFER
    // now the tracing can start (guarded by _trace_fd > 0)
    _trace_fd = temp_trace_fd;
#elif defined TRACE_USE_FORK
    // now the tracing can start (guarded by _trace_buf != dummy)
    _trace_buf = _trace_ptr;
#endif
}

void _trace_open(const char *fname, const char *suffix) {
    if (TRACE_IS_OPEN()) {
        // already opened
        return;
    }
    // Make the file name time dependent
    char timed_fname[160];
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
        perror("clock_gettime");
        return;
    }
    strftime(timed_fname, 160, fname, gmtime(&now.tv_sec));
    snprintf(trace_fname, 170, timed_fname, now.tv_nsec);

    trace_open_fname(suffix);
}

void _trace_pause(void) {
    if (!TRACE_IS_ACTIVE()) return;
    temp_trace_buf_pos = _trace_buf_pos;
#ifdef TRACE_USE_FORK
    _trace_buf = dummy;
#else
    _trace_fd = 0;
  #ifdef TRACE_USE_POSIX
    // gcc might optimize this into a memcpy call
    for (int k = 0; k < TRACE_BUF_SIZE; k++) {
        temp_trace_buf[k] = _trace_buf[k];
    }
  #endif
#endif
}

// do "_trace_ie_byte = ..." yourself after calling _trace_resume()!
void _trace_resume(void) {
    if (TRACE_IS_ACTIVE() || !TRACE_IS_OPEN()) return;
#ifdef TRACE_USE_FORK
    _trace_buf = _trace_ptr;
#else
  #ifdef TRACE_USE_POSIX
    for (int k = 0; k < TRACE_BUF_SIZE; k++) {
        _trace_buf[k] = temp_trace_buf[k];
    }
  #endif
    _trace_fd = temp_trace_fd;
#endif
    _trace_buf_pos = temp_trace_buf_pos;
}

static void trace_destroy(void) {
#ifndef TRACE_USE_RINGBUFFER
    close(temp_trace_fd);
    temp_trace_fd = 0;
#elif defined TRACE_USE_FORK
    munmap(_trace_ptr, MMAP_SIZE);
    _trace_ptr = dummy;
#endif
}

void _trace_in_fork_child(void) {
    // assumes that tracing is already inactive
    if (!TRACE_IS_OPEN() || TRACE_IS_ACTIVE()) return;

    trace_destroy();

    // copy fname_suffix and remove it
    char fname_suffix[15] = "";
    strncat(fname_suffix, &trace_fname[fname_len_wo_suffix], 14);
    trace_fname[fname_len_wo_suffix] = '\0';

    // append fork suffix
    char fork_suffix[15] = "";
    snprintf(fork_suffix, 14, "-fork-%d", _trace_fork_count);
    strncat(trace_fname, fork_suffix, 15);

    trace_open_fname(fname_suffix);
}

void _trace_close(void) {
    if (!TRACE_IS_OPEN()) {
        // already closed or never successfully opened
        return;
    }

#ifndef TRACE_USE_RINGBUFFER
    if (_trace_buf_pos != 0) {
        trace_write_rest();
    }
#elif defined TRACEFORK_POLLING
    /* put second end marker, a -1ll sign to the next page */
    _trace_buf_pos += TRACEFORK_WRITE_BLOCK_SIZE-1;
    _trace_buf_pos &= ~(TRACEFORK_WRITE_BLOCK_SIZE-1);
    *((long long *)&_trace_buf[_trace_buf_pos]) = -1ll;
#elif defined TRACEFORK_FUTEX
    if (_trace_buf_pos % TRACEFORK_WRITE_BLOCK_SIZE == 0) {
        // one extra byte (otherwise the fork would be confused)
        _trace_buf_pos += 1;
    }
    _tracefork_sync();
#endif

    // stop tracing
#ifndef TRACE_USE_RINGBUFFER
    _trace_fd = 0;
#elif defined TRACE_USE_FORK
    _trace_buf = dummy;
#endif
    // now we can call any library function without being traced
    trace_destroy();
}

#else // TRACE_USE_RINGBUFFER, without fork

void _trace_open(const char *fname, const char *suffix) {
    _trace_buf_pos = 0;
}

void _trace_close(void) {
}

void _trace_pause(void) {
    temp_trace_buf_pos = _trace_buf_pos;
}

void _trace_resume(void) {
    _trace_buf_pos = temp_trace_buf_pos;
}

void _trace_in_fork_child(void) {
    _trace_resume();
}

#endif // TRACE_USE_RINGBUFFER, without fork
