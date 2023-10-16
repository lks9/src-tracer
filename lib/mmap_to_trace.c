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

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif


#ifndef _TRACE_USE_POSIX
// taken from musl (arch/x86_64/syscall_arch.h)
static __inline long __syscall0(long n)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall1(long n, long a1)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                                                  "d"(a3) : "rcx", "r11", "memory");
    return ret;
}
#define SYS_write        1
#define SYS_madvise     28
#define SYS_nanosleep   35
#define SYS_getppid    110
#define SYS_fork        57
// end musl code
#endif

static int trace_fd;

static void my_exit(void) {
#ifdef _TRACE_USE_PTHREAD
    pthread_exit((void *)0);
#else
    exit(0);
#endif
}

// side effect free fork version
// without calling atfork etc.
pid_t my_fork(void) {
    return (pid_t)__syscall0(SYS_fork);
}

static void my_write(volatile void *ptr) {
#ifdef _TRACE_USE_POSIX
    ssize_t written = write(trace_fd, ptr, 4096);
#else
    long written = __syscall3(SYS_write, (long)trace_fd, (long)ptr, (long)4096);
#endif
    if (unlikely(written != 4096)) {
        // some write error occured
        // abort trace recording
        close(trace_fd);
        my_exit();
    }
}

void *forked_write (char *trace_fname) {
    int lowfd = open(trace_fname,
                     O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE | O_NOCTTY,
                     S_IRUSR | S_IWUSR);
#ifdef _TRACE_USE_PTHREAD
    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd number
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    trace_fd = fcntl(lowfd, F_DUPFD_CLOEXEC, lowfd + 42);
    close(lowfd);
#else
    trace_fd = lowfd;
#endif
    if (trace_fd < 0) {
        my_exit();
    }

    unsigned char *const ptr = _trace._page_ptr;
    unsigned short next_pos = 4096;
    unsigned short pos = 0;

    while (true) {
        volatile long long *next_ptr = (long long *)&(ptr[next_pos]);
        volatile long long *this_ptr = (long long *)&(ptr[pos]);
        long long next_ll;

        // wait in for loop until tracer in parent writes to next page
        for (int timeout = 100000; (next_ll = *next_ptr) == 0ll; timeout --) {
            if (timeout == 0) {
                // parent done or timeout
                my_write(this_ptr);
                close(trace_fd);
                my_exit();
            }
            const struct timespec wait_time = {0,100000};
#ifdef _TRACE_USE_POSIX
            nanosleep(&wait_time);
#else
            __syscall1(SYS_nanosleep, (long)&wait_time);
#endif
        }
        if (next_ll == -1ll) {
            // parant wrote the trace end marker -1ll
            my_write(this_ptr);
            close(trace_fd);
            my_exit();
        }

        my_write(this_ptr);
        // zero page for future access (ringbuffer!)
        for (int i = 0; i < 4096/8; i++) {
            this_ptr[i] = 0ll;
        }

        pos = next_pos;
        next_pos += 4096;
    }
}
