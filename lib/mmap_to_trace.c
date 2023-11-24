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
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>

// editable constant definitions
#ifndef TIMEOUT_NSEC
#define TIMEOUT_NSEC 10000000000 // 10 sec
#endif
#ifndef WRITE_BLOCK_SIZE
#define WRITE_BLOCK_SIZE 32768
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
    int end = len;
    while (end > 0 && ptr[end-1] != 'E') end--;
    if (end == 0) end = len;
    my_write(ptr, end);
    close(trace_fd);
    my_exit();
}

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

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

    time_t secs = TIMEOUT_NSEC / 1000000000;
    long nsecs  = TIMEOUT_NSEC % 1000000000;
    struct timespec wait_timeout = {secs, nsecs};

    while (true) {
        volatile int *next_ptr = (int *)&(ptr[next_pos]);
        volatile int *this_ptr = (int *)&(ptr[pos]);
        int next;

        // wait in for loop until tracer in parent writes to next page
        next = *next_ptr;
        if (next == 0) {
            syscall(SYS_futex, next_ptr, FUTEX_WAIT, 0, &wait_timeout);
            next = *next_ptr;
        }

        if (next == 0 || next == -1) {
            // timeout == 0 or parent wrote trace end marker -1
            write_and_exit(this_ptr, WRITE_BLOCK_SIZE);
        }

        my_write(this_ptr, WRITE_BLOCK_SIZE);

        // zero for future access (ringbuffer!)
        *this_ptr = 0;
        syscall(SYS_futex, this_ptr, FUTEX_WAKE, INT_MAX);

        pos = next_pos;
        next_pos += WRITE_BLOCK_SIZE;
    }
}
