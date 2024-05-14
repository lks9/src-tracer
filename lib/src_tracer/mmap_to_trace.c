#include <src_tracer/constants.h>

#if defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK

#include <src_tracer/trace_buf.h>

#ifndef TRACE_USE_POSIX
  #include "syscalls.h"
#endif
#ifdef TRACE_USE_PTHREAD
  #include <pthread.h>
#endif
#ifdef TRACEFORK_SYNC_UFFD
  #include "sync_uffd.h"
#endif

#ifdef TRACEFORK_FUTEX
  #include "sync_futex.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>

#include <zstd.h>

// computed constants
#define LONG_SLEEP_NSEC \
    (TRACEFORK_SHORT_SLEEP_NSEC * TRACEFORK_LONG_SLEEP_MULT)
#define SLEEP_COUNT_TIMEOUT \
    (TRACEFORK_TIMEOUT_NSEC / LONG_SLEEP_NSEC)

// other macros
#define EXIT_WHEN(cond) \
    if (cond) { \
        my_exit(); \
    }

#define CHECK_ZSTD(fn) \
    EXIT_WHEN(ZSTD_isError(fn))

static int trace_fd;

static char z_in[ZSTD_BLOCKSIZE_MAX];
static ZSTD_inBuffer in_desc = { z_in, 0, 0 };
static char z_out[ZSTD_BLOCKSIZE_MAX];
static ZSTD_outBuffer out_desc = { z_out, ZSTD_BLOCKSIZE_MAX, 0 };
static ZSTD_CCtx* cctx;

#ifdef TRACE_USE_POSIX
#define CLOSE(fd) close(fd)
#define EXIT(n) _exit(n)
#else
#define CLOSE(fd) syscall_1(SYS_close, fd)
#define EXIT(n) { \
    syscall_1(SYS_exit, n); \
    __builtin_unreachable(); \
}
#endif

__attribute__((noreturn))
static void my_exit(void) {
#ifdef TRACEFORK_SYNC_UFFD
    CLOSE(_trace_uffd);
#endif
    CLOSE(trace_fd);
    ZSTD_freeCCtx(cctx);
#ifdef TRACE_USE_PTHREAD
    pthread_exit((void *)0);
#else // in fork
    EXIT(0);
#endif
}

// write and compress
static void my_write(void *ptr, int len, bool last) {
    __builtin_memcpy(&z_in[in_desc.size], ptr, len);
#ifdef TRACEFORK_POLLING
    __builtin_memset(ptr, 0, len);
#endif
    in_desc.size += len;

    last = last || in_desc.size + TRACEFORK_WRITE_BLOCK_SIZE > ZSTD_BLOCKSIZE_MAX;
    ZSTD_EndDirective const mode = last ? ZSTD_e_end : ZSTD_e_continue;

    size_t rem;
    CHECK_ZSTD(rem = ZSTD_compressStream2(cctx, &out_desc, &in_desc, mode));
    if (last) {
        // ZSTD_e_end guarantees rem == 0 except when out buffer is full
        EXIT_WHEN(rem != 0);
#ifdef TRACE_USE_POSIX
        ssize_t written = write(trace_fd, z_out, out_desc.pos);
#else
        ssize_t written = syscall_3(SYS_write, trace_fd, (long)z_out, out_desc.pos);
#endif
        // abort trace recording on write error
        EXIT_WHEN(written != out_desc.pos);

        in_desc.pos = 0;
        in_desc.size = 0;
        out_desc.pos = 0;
    }
}

static void write_and_exit(unsigned char *ptr, int len) {
    // find were the trace ended
    int end = len;
#ifdef TRACEFORK_POLLING
    while (end > 0 && ptr[end-1] == 0) end--;
#else
    // no memset with 0 from previous write, so we can only rely on trace end marker 'E'
    while (end > 0 && ptr[end-1] != 'E') end--;
    if (end == 0) end = len;
#endif
    my_write(ptr, end, true);
    my_exit();
}

#ifdef TRACEFORK_BUSY_WAITING

static volatile long long *next_ptr_static;

static int counter = 0;
static int prev_counter = 0;

static void counter_handler(int nr) {
    if (counter == prev_counter) {
        // timeout
        // write trace end marker -1ll
        *next_ptr_static = -1ll;
    }
    prev_counter = counter;
}

#endif // TRACEFORK_BUSY_WAITING

#ifdef TRACEFORK_POLLING

#ifndef TRACEFORK_BUSY_WAITING
static void my_sleep(long nsec) {
    const struct timespec sleep_time = {
        nsec / 1000000000,
        nsec % 1000000000
    };
#ifdef TRACE_USE_POSIX
    nanosleep(&sleep_time, NULL);
#else
    syscall_2(SYS_nanosleep, (long)&sleep_time, 0);
#endif
}
#endif // TRACEFORK_BUSY_WAITING

static long long polling(volatile long long *ptr) {
    long long val;
#ifdef TRACEFORK_BUSY_WAITING
    next_ptr_static = ptr;
    while ((val = *ptr) == 0ll) {
        __builtin_ia32_pause();
    }
    counter += 1;
#else
    static bool slept_long_before = false;
    int timeout = SLEEP_COUNT_TIMEOUT;
    val = *ptr;
    if (val != 0ll) {
        slept_long_before = false;
        return val;
    }
    if (!slept_long_before) {
        // sleep short when tracing is quick
        for (int i = 0; i < TRACEFORK_LONG_SLEEP_MULT; i++) {
            my_sleep(TRACEFORK_SHORT_SLEEP_NSEC);
            val = *ptr;
            if (val != 0ll) return val;
        }
        // there were enough short sleeps...
        slept_long_before = true;
        timeout -= 1;
    }
    // sleep long when tracing is slow
    for (; timeout > 0; timeout--) {
        my_sleep(LONG_SLEEP_NSEC);
        val = *ptr;
        if (val != 0ll) return val;
    }
    // timeout!
#endif
    return val;
}

static void synchronize (unsigned char *ptr, unsigned short pos, unsigned short next_pos) {
    void *next_ptr = &(ptr[next_pos]);
    long long val = polling((long long*)next_ptr);

    if (val == 0ll || val == -1ll) {
        // timeout 0ll or trace end marker -1ll
        write_and_exit(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE);
    }
}

#endif // TRACEFORK_POLLING

#ifdef TRACEFORK_SYNC_UFFD
static void synchronize (unsigned char *ptr, unsigned short pos, unsigned short next_pos) {
    // wait until trace producer finished current segment
    struct uffd_msg msg;
    ssize_t msg_len = read(_trace_uffd, &msg, sizeof(struct uffd_msg));

    // should not happen!
    EXIT_WHEN(msg_len != sizeof(struct uffd_msg));

    if (msg.event == UFFD_EVENT_UNMAP) {
        // tracing finished
        write_and_exit(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE);
    }

    // some other event?
    // should not happen!
    EXIT_WHEN(msg.event != UFFD_EVENT_PAGEFAULT);

    // insert the trap for the next page fault
    {
        struct uffdio_writeprotect wp2;
        wp2.range.start = (unsigned long)ptr + pos;
        wp2.range.len = 4096;
        wp2.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp2);
    }

    // resolve current page fault
    if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
        // page is there, but write protected
        struct uffdio_writeprotect wp1;
        wp1.range.start = (unsigned long)ptr + next_pos;
        wp1.range.len = 4096;
        wp1.mode = 0;
        ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp1);
    } else {
        // page is missing
        struct uffdio_zeropage zp;
        zp.range.start = (unsigned long)ptr + next_pos;
        zp.range.len = 4096;
        zp.mode = 0;
        ioctl(_trace_uffd, UFFDIO_ZEROPAGE, &zp);
    }
}
#endif // TRACEFORK_SYNC_UFFD

#ifdef TRACEFORK_FUTEX

static long futex(int *uaddr, int futex_op, int val, const struct timespec *timeout) {
    return syscall_4(SYS_futex, (long)uaddr, futex_op, val, (long)timeout);
}

static void synchronize (unsigned char *ptr, unsigned short pos, unsigned short next_pos) {
#define RETRIES 5
    const struct timespec timeout = {
        (TRACEFORK_TIMEOUT_NSEC / RETRIES) / 1000000000,
        (TRACEFORK_TIMEOUT_NSEC / RETRIES) % 1000000000,
    };
    int retries = 0;
    while (*_trace_pos_futex_var == pos) {
        if (retries == RETRIES) {
            write_and_exit(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE);
        }
        futex(_trace_pos_futex_var, FUTEX_WAIT, pos, &timeout);
        retries++;
    }
#undef RETRIES
}
#endif

void *forked_write (void *trace_fname) {
    trace_fd = open(trace_fname,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY,
                    S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        my_exit();
    }

    unsigned char *const ptr = _trace_ptr;
    unsigned short next_pos = TRACEFORK_WRITE_BLOCK_SIZE;
    unsigned short pos = 0;

#ifdef TRACEFORK_BUSY_WAITING
    // timer to interrupt busy waiting
    struct sigevent sev;
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    timer_t timerid;
    sev.sigev_value.sival_ptr = &timerid;
    syscall_3(SYS_timer_create, CLOCK_BOOTTIME, (long)&sev, (long)&timerid);

    signal(SIGRTMIN, counter_handler);

    time_t secs = TRACEFORK_TIMEOUT_NSEC / 1000000000;
    long nsecs  = TRACEFORK_TIMEOUT_NSEC % 1000000000;
    struct itimerspec interv = {{secs,nsecs}, {secs,nsecs}};
    syscall_4(SYS_timer_settime, (long)timerid, (long)0, (long)&interv, (long)NULL);
#endif // TRACEFORK_BUSY_WAITING
    // initialize zstd compression
    cctx = ZSTD_createCCtx();
    EXIT_WHEN(cctx == NULL);
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, TRACEFORK_COMPRESSION_LEVEL));
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0));

    while (true) {
        synchronize(ptr, pos, next_pos);

        my_write(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE, false);

        pos = next_pos;
        next_pos += TRACEFORK_WRITE_BLOCK_SIZE;
    }
}

#endif // defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK
