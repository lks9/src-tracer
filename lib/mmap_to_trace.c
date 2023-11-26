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
#include <linux/futex.h>
#include <limits.h>
#include <sys/time.h>

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

static __inline long syscall_6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
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
#define SYS_futex      202
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

static void write_and_exit(char *ptr, int len) {
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
    trace_fd = open(trace_fname,
                    O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE | O_NOCTTY,
                    S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        my_exit();
    }

    char *const ptr = _trace_ptr;
    unsigned short next_pos = WRITE_BLOCK_SIZE;
    unsigned short pos = 0;

    time_t secs = TIMEOUT_NSEC / 1000000000;
    long nsecs  = TIMEOUT_NSEC % 1000000000;
    struct timespec wait_timeout = {secs, nsecs};

    while (true) {
        char *this_ptr = &(ptr[pos]);

        // wait until trace producer finished current segment
        int num = pos / WRITE_BLOCK_SIZE;
        int val = _trace_futex[num];
        while (val == 0) {
            int ret = syscall_6(SYS_futex, (long)&_trace_futex[num], FUTEX_WAIT, 0, (long)&wait_timeout, (long)NULL, 0);
            val = _trace_futex[num];
            if (ret != 0) break;
        }

        if (val == 0 || val == -1) {
            // timeout == 0 or parent wrote trace end marker -1
            write_and_exit(this_ptr, WRITE_BLOCK_SIZE);
        }

        my_write(this_ptr, WRITE_BLOCK_SIZE);

        // zero for future access (ringbuffer!)
        _trace_futex[num] = 0;
        syscall_6(SYS_futex, (long)&_trace_futex[num], FUTEX_WAKE, INT_MAX, (long)NULL, (long)NULL, 0);

        pos = next_pos;
        next_pos += WRITE_BLOCK_SIZE;
    }
}
