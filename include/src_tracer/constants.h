/*
   src_tracer/constants.h
   editable constant definitions
*/
#ifndef SRC_TRACER_CONSTANTS_H
#define SRC_TRACER_CONSTANTS_H

// Ringbuffer for fast tracing (no writing to disk, unless in pthread or fork)
// assumes char is 8 bit!
#define TRACE_USE_RINGBUFFER

// to write ringbuffer to disk in a separate process
//#define TRACE_USE_FORK

// do not edit here:
#ifdef TRACE_USE_FORK
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

// try to be posix compliant (conflicts with some of the other options)
//#define TRACE_USE_POSIX

// register variable for trace pos and trace ie byte
// WARNING: GCC extension, breaks the ABI
//#define TRACE_IE_BYTE_REG

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

#ifdef TRACE_USE_FORK
    // synchronization via userfault fd linux api
    //#define TRACEFORK_SYNC_UFFD

    // synchronization via futex linux api (only available when TRACE_USE_POSIX not set)
    //#define TRACEFORK_FUTEX

    // otherwise polling (do not edit here)
    #ifndef TRACEFORK_SYNC_UFFD
        #ifndef TRACEFORK_FUTEX
            #define TRACEFORK_POLLING
        #endif
    #endif

    #ifdef TRACEFORK_POLLING
        // short sleep for polling in trace fork process
        #define TRACEFORK_SHORT_SLEEP_NSEC 20000

        // long sleep multiplier when polling
        #define TRACEFORK_LONG_SLEEP_MULT 25

        // busy waiting if you really want (only available when TRACE_USE_POSIX not set)
        //#define TRACEFORK_BUSY_WAITING
    #endif

    // finish fork process after a timeout, when trace producer seems inactive
    #define TRACEFORK_TIMEOUT_NSEC 10000000000 // 10 sec

    // size of the trace blocks to consume/write at once (needs to be divisor of TRACE_BUF_SIZE)
    #define TRACEFORK_WRITE_BLOCK_SIZE 16384

    // use zstd compression
    #define TRACEFORK_ZSTD

    // zstd compression level
    #define TRACEFORK_COMPRESSION_LEVEL 3

    // debugging
    //#define TRACEFORK_DEBUG
#endif

#endif // SRC_TRACER_CONSTANSTS_H
