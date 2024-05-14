/*
   src_tracer/sync_futex.h
   synchronization between trace producer and consuming process using futex linux API
*/

#ifndef SRC_TRACER_SYNC_FUTEX_H
#define SRC_TRACER_SYNC_FUTEX_H

#include <linux/futex.h>
#include <limits.h>

extern int *_trace_pos_futex_var;

#endif // SRC_TRACER_SYNC_FUTEX_H
