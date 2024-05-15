/*
   src_tracer/sync_futex.h
   synchronization between trace producer and consuming process using futex linux API
*/

#ifndef SRC_TRACER_SYNC_FUTEX_H
#define SRC_TRACER_SYNC_FUTEX_H

#include <linux/futex.h>
#include <sys/time.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include "syscalls.h"

extern uint32_t *_trace_pos_futex_var;

static inline long futex_wait(uint32_t *uaddr, uint32_t val, const struct timespec *timeout) {
    return syscall_4(SYS_futex, (long)uaddr, FUTEX_WAIT, val, (long)timeout);
}
static inline long futex_wake(uint32_t *uaddr) {
    return syscall_3(SYS_futex, (long)uaddr, FUTEX_WAKE, INT_MAX);
}

#endif // SRC_TRACER_SYNC_FUTEX_H
