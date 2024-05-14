#include <src_tracer/constants.h>
#ifdef TRACE_USE_FORK

#define _GNU_SOURCE
#include <limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>

#ifndef TRACE_USE_POSIX

#include <errno.h>
#include "syscalls.h"

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

static
int clone3(const struct clone_args *args, size_t size)
{
	long ret = syscall_2(SYS_clone3, (long)args, size);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
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

extern void *forked_write(void *);

static int clone_function(void *arg) {
    /* new name */
#ifdef TRACE_USE_POSIX
    prctl(PR_SET_NAME, (unsigned long)"src_tracer");
#else
    syscall_2(SYS_prctl, PR_SET_NAME, (unsigned long)"src_tracer");
#endif

    /* session leader
          -> independ from the previous process session
          -> independent from terminal */
#ifdef TRACE_USE_POSIX
    setsid();
#else
    syscall_0(SYS_setsid);
#endif

    /* fork again & exit parent, to avoid any waitpid... */
#ifdef TRACE_USE_POSIX
    if (fork() != 0) _exit(0);
#else
    static const struct clone_args cl_args = {
        /* for better performance, same memory is used (no race in clone_parent_exit) */
        .flags = CLONE_VM,
    };
    clone_parent_exit(&cl_args, sizeof(struct clone_args));
#endif

    /* anything might happen to the current directory, be independent */
    //chdir("/");
    //umask(0);

    /* close any fd */
#ifdef TRACE_USE_POSIX
    /* cannot use sysconf() here, because of race conditions, see man fork(2), signal-safety(7) */
    for (int i = 0; i <= _POSIX_OPEN_MAX; i++) {
#ifdef TRACEFORK_SYNC_UFFD
        // except:
        if (i == _trace_uffd) continue;
#endif
        close(i);
    }
#elif defined TRACEFORK_SYNC_UFFD
    syscall_3(SYS_close_range, 0, _trace_uffd-1, 0);
    syscall_3(SYS_close_range, _trace_uffd+1, ~0U, 0);
#else
    syscall_3(SYS_close_range, 0, ~0U, 0);
#endif

    forked_write(arg);
    // will never return
    __builtin_unreachable();
}


// daemon process
int tracer_create_daemon(char *trace_fname) {
    int res;
#ifdef TRACE_USE_POSIX
    res = fork();
#else
    static const struct clone_args cl_args = {
        // CLONE_VFORK means that parent is suspended until child exits.
        // Unlike vfork(), child still operates on separate memory.
        .flags = CLONE_VFORK,
    };
    res = clone3(&cl_args, sizeof(struct clone_args));
#endif
    if (res == 0) {
        res = clone_function(trace_fname);
#ifdef TRACE_USE_POSIX
        _exit(res);
#else
        syscall_1(SYS_exit, res);
#endif
    }
    return res;
}

#endif // TRACE_USE_FORK
