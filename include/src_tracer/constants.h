/*
   src_tracer/constants.h
   editable constant definitions
*/
#ifndef SRC_TRACER_CONSTANTS_H
#define SRC_TRACER_CONSTANTS_H

// Ringbuffer for fast tracing (no writing to disk, unless in pthread or fork)
// assumes char is 8 bit!
#define TRACE_USE_RINGBUFFER

// to write ringbuffer to disk in a separate thread
//#define TRACE_USE_PTHREAD

// to write ringbuffer to disk in a separate process
//#define TRACE_USE_FORK

// do not edit here:
#if defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK
    #ifndef TRACE_USE_RINGBUFFER
    #define TRACE_USE_RINGBUFFER
    #endif
#endif

#ifdef TRACE_USE_RINGBUFFER
    // matches 16 bit counter, don't change this!
    #define TRACE_BUF_SIZE (1 << 16)
#else
    // change here as you want, 4096 is good for I/O
    #define TRACE_BUF_SIZE 4096
#endif

// if TRACE_USE_POSIX is not set, we use the syscall directly
#define TRACE_USE_POSIX

// text trace is meant for debugging, uncomment if you want efficiency
//#define EFFICIENT_TEXT_TRACE

// byte trace comes without any bit-tracing, trace gets is larger...
//#define BYTE_TRACE

// only used in CBMC MODE
#define RETRACE_ARR_LEN_MAX 4096

// maximum number of assertions when retracing+checking
#define ASSERT_BUF_SIZE 4096

// dump data to a ghost buffer
#define GHOST_DUMP_BUF_SIZE 4096

// maximum number of symbolic values obtained with RETRO_SYMBOLIC()
#define RETRACE_SYMBOLIC_SIZE 4096

#if defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK
    // short sleep for polling in trace fork process
    #define TRACEFORK_SHORT_SLEEP_NSEC 20000

    // long sleep multiplier when polling
    #define TRACEFORK_LONG_SLEEP_MULT 25

    // finish fork process after timeout, when for trace producing process is inactive
    #define TRACEFORK_TIMEOUT_NSEC 10000000000 // 10 sec

    // comment out if you really want busy waiting (only available when TRACE_USE_POSIX not set)
    //#define TRACEFORK_BUSY_WAITING

    // size of the trace blocks to consume/write at once (needs to be divisor of TRACE_BUF_SIZE)
    #define TRACEFORK_WRITE_BLOCK_SIZE 16384

    // zstd compression level
    #define TRACEFORK_COMPRESSION_LEVEL 3
#endif

#endif // SRC_TRACER_CONSTANSTS_H
