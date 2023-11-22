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

// editable constant definitions
#ifndef SLEEP_NSEC
#define SLEEP_NSEC 1000000
#endif
#ifndef TIMEOUT_NSEC
#define TIMEOUT_NSEC 10000000000 // 10 sec
#endif
#ifndef WRITE_BLOCK_SIZE
#define WRITE_BLOCK_SIZE 16384
#endif

// computed constant definitions
#define TIMEOUT_COUNT \
    (TIMEOUT_NSEC / SLEEP_NSEC)

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

static int trace_fd;

__attribute__((noreturn))
static void my_exit(void) {
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

static void my_write(void *ptr, int len) {
#ifdef _TRACE_USE_POSIX
    ssize_t written = write(trace_fd, ptr, len);
#else
    long written = syscall_3(SYS_write, (long)trace_fd, (long)ptr, (long)len);
#endif
    if (unlikely(written != len)) {
        // some write error occured
        // abort trace recording
        close(trace_fd);
        my_exit();
    }
}

static void write_and_exit(unsigned char *ptr, int len) {
    // find were the trace ended
    while (len > 0 && ptr[len-1] == 0) len--;
    my_write(ptr, len);
    close(trace_fd);
    my_exit();
}

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static volatile long long *next_ptr;


static bool waiting = false;
static bool poll_cond = true;
static int counter = 0;
static int prev_counter = 0;

static void timer_handler(int nr) {
    if (!waiting) return;
    if (counter == prev_counter) {
        // timeout
        poll_cond = false;
    } else {
        prev_counter = counter;
    }
}

void *forked_write (char *trace_fname) {
    int trace_fd = open(trace_fname,
                        O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE | O_NOCTTY,
                        S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        my_exit();
    }

    unsigned char *const ptr = _trace_ptr;
    unsigned short next_pos = WRITE_BLOCK_SIZE;
    unsigned short pos = 0;

    // timer to interrupt busy waiting
    struct sigevent sev;
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    timer_t timerid;
    sev.sigev_value.sival_ptr = &timerid;
    syscall_3(SYS_timer_create, CLOCK_BOOTTIME, (long)&sev, (long)&timerid);

    signal(SIGRTMIN, timer_handler);

    struct itimerspec interv = {{0, SLEEP_NSEC}, {0, SLEEP_NSEC}};
    syscall_4(SYS_timer_settime, (long)timerid, (long)0, (long)&interv, (long)NULL);

    while (true) {
        next_ptr = (long long *)&(ptr[next_pos]);
        unsigned char *this_ptr = &(ptr[pos]);
        long long next_ll;

        // wait in for loop until tracer in parent writes to next page
        waiting = true;
        counter += 1;
        // 1. first try
        next_ll = *next_ptr;
        // 2. busy waiting
        while (poll_cond) {
            if (next_ll != 0ll) break;
            __builtin_ia32_pause();
            next_ll = *next_ptr;
        }
        poll_cond = true;
        // 3. sleep waiting
        for (int timeout = 0; timeout < TIMEOUT_COUNT; timeout++) {
            if (next_ll != 0ll) break;
            // pause() causes timer_handler() to set poll_cond=false for the next iteration
            pause();
            next_ll = *next_ptr;
        }
        waiting = false;

        if (next_ll == 0ll || next_ll == -1ll) {
            // timeout (indicated by 0ll) or parent wrote trace end marker -1ll
            write_and_exit(this_ptr, WRITE_BLOCK_SIZE);
        }

        my_write(this_ptr, WRITE_BLOCK_SIZE);
        // zero page for future access (ringbuffer!)
        __builtin_memset(this_ptr, 0, WRITE_BLOCK_SIZE);

        pos = next_pos;
        next_pos += WRITE_BLOCK_SIZE;
    }
}
