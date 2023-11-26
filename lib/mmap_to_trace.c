#include <src_tracer/_after_instrument.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include <zstd.h>

// editable constant definitions
#ifndef SHORT_SLEEP_NSEC
#define SHORT_SLEEP_NSEC 20000
#endif
#ifndef LONG_SLEEP_MULT
#define LONG_SLEEP_MULT 25
#endif
#ifndef TIMEOUT_NSEC
#define TIMEOUT_NSEC 10000000000 // 10 sec
#endif
#ifndef BUSY_WAITING
// comment out if you really want busy waiting
//#define BUSY_WAITING
#endif
#ifndef WRITE_BLOCK_SIZE
#define WRITE_BLOCK_SIZE 16384
#endif
#ifndef COMPRESSION_LEVEL
#define COMPRESSION_LEVEL 3
#endif

// computed constants
#define LONG_SLEEP_NSEC \
    (SHORT_SLEEP_NSEC * LONG_SLEEP_MULT)
#define SLEEP_COUNT_TIMEOUT \
    (TIMEOUT_NSEC / LONG_SLEEP_NSEC)

#ifndef _TRACE_USE_POSIX
// taken from musl (arch/x86_64/syscall_arch.h)
static __inline long syscall_0(long n)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

static __inline long syscall_1(long n, long a1)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static __inline long syscall_3(long n, long a1, long a2, long a3)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                                                  "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static __inline long syscall_4(long n, long a1, long a2, long a3, long a4)
{
       unsigned long ret;
       register long r10 __asm__("r10") = a4;
       __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                                                 "d"(a3), "r"(r10): "rcx", "r11", "memory");
       return ret;
}

#define SYS_write        1
#define SYS_madvise     28
#define SYS_nanosleep   35
#define SYS_getppid    110
#define SYS_fork        57
#define SYS_timer_create        222
#define SYS_timer_settime       223
#define SYS_timer_gettime       224
// end musl code
#endif

// other macros
#define EXIT_WHEN(cond) \
    if (cond) { \
        my_exit(); \
    }

#define CHECK_ZSTD(fn) \
    EXIT_WHEN(ZSTD_isError(fn))

static int trace_fd;

static char buffIn[ZSTD_BLOCKSIZE_MAX];
static ZSTD_inBuffer input = { buffIn, 0, 0 };
static char buffOut[ZSTD_BLOCKSIZE_MAX];
static ZSTD_outBuffer output = { buffOut, ZSTD_BLOCKSIZE_MAX, 0 };
static ZSTD_CCtx* cctx;

__attribute__((noreturn))
static void my_exit(void) {
    close(trace_fd);
    ZSTD_freeCCtx(cctx);
#ifdef _TRACE_USE_PTHREAD
    pthread_exit((void *)0);
#else
    exit(0);
#endif
}

// side effect free fork version
// without calling atfork etc.
__attribute__((returns_twice))
pid_t my_fork(void) {
#ifdef _TRACE_USE_POSIX
    return fork();
#else
    return (pid_t)syscall_0(SYS_fork);
#endif
}

// write and compress
static void my_write(void *ptr, int len, bool last) {
    memcpy(&buffIn[input.pos], ptr, len);

    input.size += len;
    last = last || input.size == ZSTD_BLOCKSIZE_MAX;
    ZSTD_EndDirective const mode = last ? ZSTD_e_end : ZSTD_e_continue;

    CHECK_ZSTD(ZSTD_compressStream2(cctx, &output, &input, mode));
    if (last) {
        ssize_t written = write(trace_fd, buffOut, output.pos);
        // abort trace recording when write error
        EXIT_WHEN(written != output.pos);

        input.pos = 0;
        input.size = 0;
        output.pos = 0;
    }
}

static void write_and_exit(unsigned char *ptr, int len) {
    // find were the trace ended
    while (len > 0 && ptr[len-1] == 0) len--;
    my_write(ptr, len, true);
    my_exit();
}

static volatile long long *next_ptr;

#ifdef BUSY_WAITING

static int counter = 0;
static int prev_counter = 0;

static void counter_handler(int nr) {
    if (counter == prev_counter) {
        // timeout
        // write trace end marker -1ll
        *next_ptr = -1ll;
    }
    prev_counter = counter;
}

#else // BUSY_WAITING

static void my_sleep(long nsec) {
    const struct timespec sleep_time = {0, nsec};
#ifdef _TRACE_USE_POSIX
    nanosleep(&sleep_time);
#else
    syscall_1(SYS_nanosleep, (long)&sleep_time);
#endif
}

#endif // BUSY_WAITING

void *forked_write (void *trace_fname) {
    char fname_zstd[200];
    strncat(fname_zstd, (char*)trace_fname, 195);
    strncat(fname_zstd, ".zst", 5);
    trace_fd = open(fname_zstd,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY,
                    S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        my_exit();
    }

    unsigned char *const ptr = _trace_ptr;
    unsigned short next_pos = WRITE_BLOCK_SIZE;
    unsigned short pos = 0;

#ifdef BUSY_WAITING
    // timer to interrupt busy waiting
    struct sigevent sev;
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    timer_t timerid;
    sev.sigev_value.sival_ptr = &timerid;
    syscall_3(SYS_timer_create, CLOCK_BOOTTIME, (long)&sev, (long)&timerid);

    signal(SIGRTMIN, counter_handler);

    time_t secs = TIMEOUT_NSEC / 1000000000;
    long nsecs  = TIMEOUT_NSEC % 1000000000;
    struct itimerspec interv = {{secs,nsecs}, {secs,nsecs}};
    syscall_4(SYS_timer_settime, (long)timerid, (long)0, (long)&interv, (long)NULL);
#else
    bool slept_before = false;
#endif
    // initialize zstd compression
    cctx = ZSTD_createCCtx();
    EXIT_WHEN(cctx == NULL);
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, COMPRESSION_LEVEL));
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0));

    while (true) {
        next_ptr = (long long *)&(ptr[next_pos]);
        unsigned char *this_ptr = &(ptr[pos]);
        long long next_ll;

        // wait in for loop until tracer in parent writes to next page
#ifdef BUSY_WAITING
        while ((next_ll = *next_ptr) == 0ll) {
            __builtin_ia32_pause();
        }
        counter += 1;
#else
        if (!slept_before) {
            // sleep short when tracing is quick
            for (int i = 0; i < LONG_SLEEP_MULT; i++) {
                next_ll = *next_ptr;
                if (next_ll != 0ll) break;
                my_sleep(SHORT_SLEEP_NSEC);
            }
        } else {
            next_ll = *next_ptr;
        }
        slept_before = false;
        for (int timeout = 0; timeout < SLEEP_COUNT_TIMEOUT; timeout++) {
            if (next_ll != 0ll) break;
            my_sleep(LONG_SLEEP_NSEC);
            next_ll = *next_ptr;
            slept_before = true;
        }
#endif
        if (next_ll == 0ll || next_ll == -1ll) {
            // timeout (indicated by 0ll) or parent wrote trace end marker -1ll
            write_and_exit(this_ptr, WRITE_BLOCK_SIZE);
        }

        my_write(this_ptr, WRITE_BLOCK_SIZE, false);
        // zero page for future access (ringbuffer!)
        __builtin_memset(this_ptr, 0, WRITE_BLOCK_SIZE);

        pos = next_pos;
        next_pos += WRITE_BLOCK_SIZE;
    }
}
