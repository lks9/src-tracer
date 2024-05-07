#include <src_tracer/constants.h>
#include <src_tracer/trace_elem.h>
#include <src_tracer/trace_buf.h>
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
#include <sys/prctl.h>
#include <pthread.h>

#ifndef TRACE_USE_POSIX
  #include "syscalls.h"
#endif
#ifdef TRACEFORK_SYNC_UFFD
  #include "sync_uffd.h"
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

// trace buffer
#if defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK
  static unsigned char dummy[TRACE_BUF_SIZE] __attribute__ ((aligned (4096)));
  void __attribute__((aligned(4096))) *_trace_ptr = dummy;
  __attribute__((aligned(4096))) unsigned char *restrict _trace_buf = dummy;
#else
  unsigned char _trace_buf[TRACE_BUF_SIZE];
#endif

// trace position
#ifdef TRACE_USE_RINGBUFFER
  unsigned short _trace_buf_pos = 0;
#else
  int _trace_buf_pos = 0;
#endif

// trace ie byte
unsigned char _trace_ie_byte = _TRACE_SET_IE_INIT;

// trace file name
static __attribute__((unused)) char trace_fname[200] = "";

// userfault fd
#ifdef TRACEFORK_SYNC_UFFD
  int _trace_uffd;
#endif

// temporary stuff
static __attribute__((unused)) unsigned char temp_trace_buf[TRACE_BUF_SIZE];
static __attribute__((unused)) int temp_trace_buf_pos;
static __attribute__((unused)) int temp_trace_fd;

#ifndef TRACE_USE_RINGBUFFER

void _trace_write(const void *buf) {
    if (trace_fd <= 0) return;
#ifdef TRACE_USE_POSIX
    ssize_t written = write(trace_fd, buf, TRACE_BUF_SIZE);
#else
    // Use syscall_3 to avoid recursive calls
    long written = syscall_3(SYS_write, (long)trace_fd, (long)buf, (long)TRACE_BUF_SIZE);
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
#ifdef TRACE_USE_POSIX
    ssize_t written = write(trace_fd, buf, count);
#else
    // Use syscall_3 to avoid recursive calls
    long written = syscall_3(SYS_write, (long)trace_fd, (long)buf, (long)count);
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
#ifdef TRACE_USE_POSIX
    write(trace_fd, _trace_buf, _trace_buf_pos);
#else
    // Use syscall_3 to avoid recursive calls
    syscall_3(SYS_write, (long)trace_fd, (long)_trace_buf, (long)_trace_buf_pos);
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
}

void _trace_before_fork(void) {
    if (trace_fd <= 0) {
        // tracing has already been aborted!
        return;
    }
    _trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_FORK, _trace_fork_count);

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
        _trace_ie_byte = _TRACE_SET_IE_INIT;

        // _TRACE_NUM(pid < 0 ? -1 : 1);
        _TRACE_IF();
        return pid;
    }
    // we are in a fork
    close(temp_trace_fd);
    temp_trace_fd = 0;
    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", _trace_fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    int lowfd = open(trace_fname, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);
    int fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);

    // now the tracing can start (guarded by trace_fd > 0)
    trace_fd = fd;
    _trace_buf_pos = 0;
    _trace_ie_byte = _TRACE_SET_IE_INIT;

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

#elif defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK
// use the ringbuffer and write in a separate pthread/fork

extern void *forked_write(void *);
#ifdef TRACE_USE_PTHREAD
static pthread_t writer_tid;
#endif

extern
__attribute__((returns_twice))
pid_t my_fork(void);

static void create_trace_process(void) {
    // reserve memory for the trace buffer
#ifdef TRACEFORK_SYNC_UFFD
    const size_t mmap_size = TRACE_BUF_SIZE + 4096;
#else
    const size_t mmap_size = TRACE_BUF_SIZE;
#endif
#ifdef TRACE_USE_PTHREAD
    const int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
#else
    const int mmap_flags = MAP_SHARED | MAP_ANONYMOUS;
#endif
    _trace_ptr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
    if (_trace_ptr == MAP_FAILED) {
        _trace_ptr = dummy;
        perror("mmap");
        return;
    }

#ifdef TRACEFORK_SYNC_UFFD
    // we set up uffd events when (half of) trace pages are filled
    // then trace writer can write in second thread/process
    _trace_uffd = syscall(SYS_userfaultfd, UFFD_USER_MODE_ONLY);
    if (_trace_uffd == -1) {
        _trace_ptr = dummy;
        perror("userfaultfd");
        return;
    }
    struct uffdio_api uffdio_api;
    uffdio_api.api = UFFD_API;
    uffdio_api.features = UFFD_FEATURE_EVENT_UNMAP | UFFD_FEATURE_PAGEFAULT_FLAG_WP;
    if (ioctl(_trace_uffd, UFFDIO_API, &uffdio_api) == -1) {
        perror("uffdio api");
        _trace_ptr = dummy;
        return;
    }

    // do not generate page fault for first page
    *(unsigned char*)_trace_ptr = -1;

    // register page ranges to track
    struct uffdio_register uffdio_register;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MISSING;
    uffdio_register.range.len = 4096;
    unsigned short i = 0;
    do {
        uffdio_register.range.start = (unsigned long) _trace_ptr + i;
        if (ioctl(_trace_uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
            perror("uffdio register");
            _trace_ptr = dummy;
            return;
        }
        i += TRACEFORK_WRITE_BLOCK_SIZE;
    } while (i != 0);

    // only used as a hack to finish tracing by creating an unmap event
    uffdio_register.range.start = (unsigned long) _trace_ptr + 65536;
    if (ioctl(_trace_uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
        perror("uffdio register");
        _trace_ptr = dummy;
        return;
    }
#endif

#ifdef TRACE_USE_PTHREAD
    pthread_create(&writer_tid, NULL, &forked_write, trace_fname);
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
        __builtin_unreachable();
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
    _trace_buf_pos = 0;
    _trace_ie_byte = _TRACE_SET_IE_INIT;
}

void _trace_before_fork(void) {
    if (_trace_buf == dummy) {
        // tracing has already been aborted!
        return;
    }
    _trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_FORK, _trace_fork_count);

    temp_trace_buf_pos = _trace_buf_pos;

    // stop tracing
    _trace_buf = dummy;
}

int _trace_after_fork(int pid) {
    if (_trace_ptr == dummy) {
        // tracing has already been aborted!
        return pid;
    }
    if (pid != 0) {
        // we are in the parent
        // resume tracing
        _trace_buf = _trace_ptr;
        _trace_buf_pos = temp_trace_buf_pos;
        _trace_ie_byte = _TRACE_SET_IE_INIT;

        // _TRACE_NUM(pid < 0 ? -1 : 1);
        _TRACE_IF();
        return pid;
    }
    // we are in a fork

    // just to be sure
    _trace_buf = dummy;

    // unmap old trace buffer
    munmap(_trace_ptr, TRACE_BUF_SIZE);
    _trace_ptr = dummy;

    char fname_suffix[20];
    snprintf(fname_suffix, 20, "-fork-%d.trace", _trace_fork_count);
    strncat(trace_fname, fname_suffix, 20);
    //printf("Trace to: %s\n", trace_fname);

    create_trace_process();

    // now the tracing can start (guarded by _trace_ptr != dummy)
    _trace_buf = _trace_ptr;
    _trace_buf_pos = 0;
    _trace_ie_byte = _TRACE_SET_IE_INIT;

    // _TRACE_NUM(pid);
    _TRACE_ELSE();
    return pid;
}

void _trace_close(void) {
    if (_trace_buf == dummy || _trace_ptr == dummy) {
        // already closed, paused or never successfully opened
        _trace_buf = dummy;
        _trace_ptr = dummy;
        return;
    }
    // put trace end marker 'E' on the trace
    _TRACE_END();

#ifdef TRACEFORK_POLLING
    /* put second end marker, a -1ll sign to the next page */
    _trace_buf_pos += TRACEFORK_WRITE_BLOCK_SIZE-1;
    _trace_buf_pos &= ~(TRACEFORK_WRITE_BLOCK_SIZE-1);
    for (int i = 0; i < 8; i++) {
        _trace_buf[_trace_buf_pos] = 0xff;
        _trace_buf_pos += 1;
    }
#endif

    // stop tracing
    _trace_buf = dummy;

#ifdef TRACEFORK_SYNC_UFFD
    // we never use this memory
    // hack to generate an uffd event to stop the trace writer
    munmap(_trace_ptr + TRACE_BUF_SIZE, 4096);
#endif

    // now we can safely call library functions
#ifdef TRACE_USE_PTHREAD
    pthread_join(writer_tid, NULL);
#endif
    munmap(_trace_ptr, TRACE_BUF_SIZE);
    _trace_ptr = dummy;
}

#else // TRACE_USE_RINGBUFFER, without fork or pthread

void _trace_open(const char *fname) {
    _trace_ie_byte = _TRACE_SET_IE_INIT;
    _trace_buf_pos = 0;
}

void _trace_close(void) {
    _TRACE_END();
}

void _trace_before_fork(void) {
    _trace_fork_count += 1;
    _TRACE_NUM(_TRACE_SET_FORK, _trace_fork_count);
}

int _trace_after_fork(int pid) {
    if (pid != 0) {
        // we are in the parent
        _TRACE_IF();
        return pid;
    }
    // we are in a fork
    _TRACE_ELSE();
    return pid;
}

#endif // TRACE_USE_RINGBUFFER
