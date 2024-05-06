/*
   src_tracer/constants.h
   editable constant definitions
*/
#ifndef SRC_TRACER_CONSTANTS_H
#define SRC_TRACER_CONSTANTS_H

// Ringbuffer for fast tracing without writing to disk
// assumes char is 8 bit!
#define TRACE_USE_RINGBUFFER

#ifdef TRACE_USE_RINGBUFFER
    // matches 16 bit counter, don't change this!
    #define TRACE_BUF_SIZE (1 << 16)
#else
    // change here as you want, 4096 is good for I/O
    #define TRACE_BUF_SIZE 4096
#endif

// if TRACE_USE_POSIX_WRITE is not set we use the syscall directly
#define TRACE_USE_POSIX_WRITE

// text trace is meant for debugging, uncomment if you want efficiency
//#define EFFICIENT_TEXT_TRACE

// byte trace comes without any bit-tracing, trace gets is larger...
//#define BYTE_TRACE

// only used in CBMC MODE
#define RETRACE_ARR_LEN_MAX 4096
#define ASSERT_BUF_SIZE 4096

#endif // SRC_TRACER_CONSTANSTS_H
