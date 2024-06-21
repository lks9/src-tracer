#include <src_tracer/constants.h>

#ifdef TRACE_USE_FORK

#include <src_tracer/trace_mode.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#ifndef TRACE_USE_POSIX
  #include "syscalls.h"
  #include <linux/sched.h>
  #include <sched.h>
  #include <sys/prctl.h>
  #include <linux/close_range.h>
  #if defined TRACEFORK_SYNC_UFFD || defined TRACEFORK_UFFD_BREAK
    #include "sync_uffd.h"
  #endif
  #ifdef TRACEFORK_FUTEX
    #include "sync_futex.h"
  #endif
#endif

#ifdef TRACEFORK_ZSTD
  #include <zstd.h>
#endif

#ifndef TRACEFORK_DEBUG
  #define perror(x) /* nothing here */
#else
  #include <stdio.h>
#endif

// computed constants
#define LONG_SLEEP_NSEC \
    (TRACEFORK_SHORT_SLEEP_NSEC * TRACEFORK_LONG_SLEEP_MULT)
#define SLEEP_COUNT_TIMEOUT \
    (TRACEFORK_TIMEOUT_NSEC / LONG_SLEEP_NSEC)

// other macros
#ifdef TRACEFORK_DEBUG
#define EXIT_WHEN(cond, str) \
    if (cond) { \
        fprintf(stderr, "[%s:%d] %s", __FILE__, __LINE__, str); \
        my_exit(); \
    }
#else
#define EXIT_WHEN(cond, str) \
    if (cond) { \
        my_exit(); \
    }
#endif

#define CHECK_ZSTD(fn) { \
    size_t const err = (fn); \
    EXIT_WHEN(ZSTD_isError(err), ZSTD_getErrorName(err)); \
}

#ifdef TRACEFORK_ZSTD
static char z_in[ZSTD_BLOCKSIZE_MAX];
static ZSTD_inBuffer in_desc = { z_in, 0, 0 };
static char z_out[ZSTD_BLOCKSIZE_MAX];
static ZSTD_outBuffer out_desc = { z_out, ZSTD_BLOCKSIZE_MAX, 0 };
static ZSTD_CCtx* cctx;
#endif

static int trace_fd;

__attribute__((noreturn))
static void my_exit(void) {
#if defined TRACEFORK_SYNC_UFFD || defined TRACEFORK_UFFD_BREAK
    close(_trace_uffd);
#endif
    close(trace_fd);
#ifdef TRACEFORK_ZSTD
    ZSTD_freeCCtx(cctx);
#endif
    _exit(0);
}

#ifdef TRACEFORK_ZSTD

// write and compress
static void my_write(void *ptr, int len, bool last, unsigned long last_block) {
    __builtin_memcpy(&z_in[in_desc.size], ptr, len);
#ifdef TRACEFORK_POLLING
    // reset to 0 for future polling
    *(long long*)ptr = 0;
#ifdef TRACEFORK_UFFD_BREAK
    if (!last) {
        // everything copied, clear potential wp pagefaults
        struct uffdio_writeprotect wp1;
        wp1.range.start = last_block;
        wp1.range.len = 4096;
        wp1.mode = 0;
        ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp1);
    }
#endif
#endif
    in_desc.size += len;

    last = last || in_desc.size + TRACEFORK_WRITE_BLOCK_SIZE > ZSTD_BLOCKSIZE_MAX;
    ZSTD_EndDirective const mode = last ? ZSTD_e_end : ZSTD_e_continue;

    size_t rem;
    CHECK_ZSTD(rem = ZSTD_compressStream2(cctx, &out_desc, &in_desc, mode));
    if (last) {
        // ZSTD_e_end guarantees rem == 0 except when out buffer is full
        EXIT_WHEN(rem != 0, "");
        ssize_t written = write(trace_fd, z_out, out_desc.pos);
        // abort trace recording on write error
        EXIT_WHEN(written != out_desc.pos, "");

        in_desc.pos = 0;
        in_desc.size = 0;
        out_desc.pos = 0;
    }
}

#else // not TRACEFORK_ZSTD

// write uncompressed
static void my_write(void *ptr, int len, bool last) {
    ssize_t written = write(trace_fd, ptr, len);
#ifdef TRACEFORK_POLLING
    *(long long*)ptr = 0;
#endif
    // abort trace recording on write error
    EXIT_WHEN(written != len, "");
}

#endif

static void write_and_exit(unsigned char *ptr, int len) {
    // find were the trace ended
    // remove any 0s at the end
    while (len > 0 && ptr[len-1] == 0) len--;
    // no memset with 0 after previous write, so we can only rely on trace end marker 'E'
    int end = len;
    while (end > 0 && ptr[end-1] != 'E') end--;
    // no 'E' found?
    if (end == 0) end = len;
    my_write(ptr, end, true, 0);
    my_exit();
}

#if 0 // def TRACEFORK_BUSY_WAITING

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
    syscall_1(SYS_rt_sigreturn, 0);
}

#endif // TRACEFORK_BUSY_WAITING

#ifdef TRACEFORK_POLLING

#ifndef TRACEFORK_BUSY_WAITING
static void my_sleep(long nsec) {
    const struct timespec sleep_time = {
        nsec / 1000000000,
        nsec % 1000000000
    };
    nanosleep(&sleep_time, NULL);
}
#endif // TRACEFORK_BUSY_WAITING

static long long polling(volatile long long *ptr, unsigned long trace_ptr, unsigned short pos, unsigned short next_pos) {
    long long val;
#ifdef TRACEFORK_BUSY_WAITING
    //next_ptr_static = ptr;
    while ((val = *ptr) == 0ll) {
        __builtin_ia32_pause();
    }
    //counter += 1;
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
#ifdef TRACEFORK_UFFD_BREAK
    {
        // insert the trap for the last page
        struct uffdio_writeprotect wp2;
        wp2.range.start = (trace_ptr + next_pos - 4096) % TRACE_BUF_SIZE;
        wp2.range.len = 4096;
        wp2.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp2);
    }
#endif
    return val;
}

static void synchronize (unsigned char *ptr, unsigned short pos, unsigned short next_pos) {
    void *next_ptr = &(ptr[next_pos]);
    long long val = polling((long long*)next_ptr, (unsigned long)ptr, pos, next_pos);

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
    EXIT_WHEN(msg_len != sizeof(struct uffd_msg), "");

    if (msg.event == UFFD_EVENT_UNMAP) {
        // tracing finished
        write_and_exit(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE);
    }

    // some other event?
    // should not happen!
    EXIT_WHEN(msg.event != UFFD_EVENT_PAGEFAULT, "");

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
static void synchronize (unsigned char *ptr, unsigned short pos, unsigned short next_pos) {
    const struct timespec timeout = {
        .tv_sec = TRACEFORK_TIMEOUT_NSEC / 1000000000,
        .tv_nsec = TRACEFORK_TIMEOUT_NSEC % 1000000000,
    };
    unsigned short cur_val;
    while ((cur_val = *_trace_pos_futex_var) == pos) {
        switch(futex_wait(_trace_pos_futex_var, pos, &timeout)) {
        case -EAGAIN:
        case -EINTR:
        case 0:
            /* let's check the variable again */
            continue;
        case -ETIMEDOUT:
            /* timeout */
            write_and_exit(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE);
        default:
            /* some other error */
            EXIT_WHEN(true, "");
        }
    }
    unsigned short rem = cur_val - pos;
    if (rem < TRACEFORK_WRITE_BLOCK_SIZE) {
        /* finished tracing, only rem remaining */
        my_write(&(ptr[pos]), rem, true);
        my_exit();
    }
}
#endif

static void forked_main (void) {

    unsigned char *const ptr = _trace_ptr;
    unsigned short next_pos = TRACEFORK_WRITE_BLOCK_SIZE;
    unsigned short pos = 0;

#if 0 // def TRACEFORK_BUSY_WAITING
    // register timer to interrupt busy waiting
    struct sigevent sev;
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMAX;
    timer_t timerid;
    sev.sigev_value.sival_ptr = &timerid;
    syscall_3(SYS_timer_create, CLOCK_BOOTTIME, (long)&sev, (long)&timerid);

    // register signal handler
    signal(SIGRTMAX, counter_handler);

    // start the timer
    time_t secs = TRACEFORK_TIMEOUT_NSEC / 1000000000;
    long nsecs  = TRACEFORK_TIMEOUT_NSEC % 1000000000;
    struct itimerspec interv = {{secs,nsecs}, {secs,nsecs}};
    syscall_4(SYS_timer_settime, (long)timerid, (long)0, (long)&interv, (long)NULL);
#endif // TRACEFORK_BUSY_WAITING
#ifdef TRACEFORK_ZSTD
    // initialize zstd compression
    cctx = ZSTD_createCCtx();
    EXIT_WHEN(cctx == NULL, "");
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, TRACEFORK_COMPRESSION_LEVEL));
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0));
#endif

    while (true) {
        synchronize(ptr, pos, next_pos);

        my_write(&(ptr[pos]), TRACEFORK_WRITE_BLOCK_SIZE, false, (unsigned long)&(ptr[(unsigned short)(pos+61440)]));

        pos = next_pos;
        next_pos += TRACEFORK_WRITE_BLOCK_SIZE;
    }
}

#ifndef TRACE_USE_POSIX
// custom fork / clone functions
static
int clone3(const struct clone_args *args, size_t size)
{
	long ret = syscall_2(SYS_clone3, (long)args, size);
#ifdef TRACEFORK_DEBUG
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
#endif
    return (int)ret;
}

/*
  Fork using clone syscall, then exit in parent and return in child.
  Safe to use with CLONE_VM, as there is no memory write access between the two syscalls in the
  parent (not even stack is used), so there cannot be a race condition with the child.
  (Relies on noipa and Os attribute, otherwise some stack push and pop could break this!)
*/

static long
__attribute__((noipa,optimize("Os")))
clone_parent_exit(const struct clone_args *args, size_t size)
{
	long ret = syscall_2(SYS_clone3, (long)args, size);
    if (ret > 0) {
        syscall_1(SYS_exit, 0);
        __builtin_unreachable();
    }
    return ret;
}

#endif // not TRACE_USE_POSIX

static void fork_parent_exit(void) {
#ifdef TRACE_USE_POSIX
    if (fork() != 0) _exit(0);
#else
    static const struct clone_args cl_args = {
        /* for better performance, same memory is used (no race in clone_parent_exit) */
        .flags = CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_SIGHAND,
    };
    clone_parent_exit(&cl_args, sizeof(struct clone_args));
#endif
}

static void setup_uffd(void) {
#if defined TRACEFORK_SYNC_UFFD || defined TRACEFORK_UFFD_BREAK
    // we set up uffd events when (half of) trace pages are filled
    // then trace writer can write in second thread/process
    _trace_uffd = syscall(SYS_userfaultfd, UFFD_USER_MODE_ONLY
#ifdef TRACEFORK_UFFD_BREAK
                                         | O_NONBLOCK
#endif
            );
    if (_trace_uffd < 0) {
#ifdef TRACEFORK_DEBUG
        errno = -_trace_uffd;
        perror("userfaultfd");
#endif
        _exit(0);
    }
    struct uffdio_api uffdio_api = {
        .api = UFFD_API,
        .features = 0
#ifdef TRACEFORK_SYNC_UFFD
                  | UFFD_FEATURE_EVENT_UNMAP
                  | UFFD_FEATURE_MISSING_SHMEM
#endif
                  | UFFD_FEATURE_WP_HUGETLBFS_SHMEM,
    };
    if (ioctl(_trace_uffd, UFFDIO_API, &uffdio_api) == -1) {
        perror("uffdio api");
        _exit(0);
    }

#ifdef TRACEFORK_SYNC_UFFD
    // do not generate page fault for first page
    *(unsigned char*)_trace_ptr = 0xff;
#endif

    // register page ranges to track
    struct uffdio_register uffdio_register = {
        .mode = UFFDIO_REGISTER_MODE_WP
#ifdef TRACEFORK_SYNC_UFFD
              | UFFDIO_REGISTER_MODE_MISSING
#endif
              ,
        .range.len = 4096,
    };
    for (int i = 0; i < TRACE_BUF_SIZE; i += TRACEFORK_WRITE_BLOCK_SIZE) {
#ifdef TRACEFORK_UFFD_BREAK
        // do not generate a missing page fault, only wp
        ((unsigned char*)_trace_ptr)[i] = 0;
        uffdio_register.range.start = (unsigned long) _trace_ptr + i + TRACEFORK_WRITE_BLOCK_SIZE - 4096;
#else
        uffdio_register.range.start = (unsigned long) _trace_ptr + i;
#endif
        if (ioctl(_trace_uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
            perror("uffdio register");
            _exit(0);
        }
    }
#ifdef TRACEFORK_UFFD_BREAK
    // insert the trap for the last page
    {
        struct uffdio_writeprotect wp2;
        wp2.range.start = (unsigned long)_trace_ptr + TRACE_BUF_SIZE - 4096;
        wp2.range.len = 4096;
        wp2.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        ioctl(_trace_uffd, UFFDIO_WRITEPROTECT, &wp2);
    }
#endif
#endif
}

static int clone_function(void *trace_fname) {
#ifndef TRACE_USE_POSIX
    /* new name */
    prctl(PR_SET_NAME, (unsigned long)"src_tracer");
#endif

    /* session leader
          -> independ from the previous process session
          -> independent from terminal */
    setsid();

    /* anything might happen to the current directory, be independent */
    //chdir("/");
    //umask(0);

    /* close any fd */
#ifdef TRACEFORK_DEBUG
  #define FIRST_FD 3
#else
  #define FIRST_FD 0
#endif
#ifdef TRACE_USE_POSIX
    /* cannot use sysconf() here, because of race conditions, see man fork(2), signal-safety(7) */
    for (int fd = FIRST_FD; fd <= _POSIX_OPEN_MAX; fd++) {
  #if defined TRACEFORK_SYNC_UFFD || defined TRACEFORK_UFFD_BREAK
        if (fd == _trace_uffd) continue;
  #endif
        close(fd);
    }
#else
  #if defined TRACEFORK_SYNC_UFFD || defined TRACEFORK_UFFD_BREAK
    if (FIRST_FD < trace_fd) {
        syscall_3(SYS_close_range, FIRST_FD, _trace_uffd - 1, CLOSE_RANGE_UNSHARE);
    }
    syscall_3(SYS_close_range, _trace_uffd + 1, ~0U, CLOSE_RANGE_UNSHARE);
  #else
    syscall_3(SYS_close_range, FIRST_FD, ~0U, CLOSE_RANGE_UNSHARE);
  #endif
#endif

    trace_fd = open(trace_fname,
                     O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY,
                     S_IRUSR | S_IWUSR);
    if (trace_fd < 0) {
        perror("open trace_fd");
        _exit(0);
    }

    /* fork again & exit parent, to avoid any waitpid... */
    fork_parent_exit();

    forked_main();
    // will never return
    __builtin_unreachable();
}


// daemon process
int tracer_create_daemon(char *trace_fname) {
    int res;

    setup_uffd();

#ifdef TRACE_USE_POSIX
    res = fork();
#else
    static const struct clone_args cl_args = {
        // CLONE_VFORK means that parent is suspended until child exits.
        // Unlike CLONE_VM or vfork(), child still operates on separate memory.
        .flags = CLONE_VFORK | CLONE_FILES | CLONE_FS,
    };
    res = clone3(&cl_args, sizeof(struct clone_args));
#endif
    if (res == 0) {
        clone_function(trace_fname);
        _exit(res);
    }
#if defined TRACEFORK_SYNC_UFFD || defined TRACFORK_UFFD_BREAK
    // only needed in the child process
    close(_trace_uffd);
#endif
    return res;
}


#endif // TRACE_USE_FORK
