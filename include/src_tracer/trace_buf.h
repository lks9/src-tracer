/*
   src_tracer/trace_buf.h
   anything related to the trace buffer
*/
#ifndef SRC_TRACER_TRACE_BUF_H
#define SRC_TRACER_TRACE_BUF_H

#include "src_tracer/constants.h"

// trace buffer
#if defined TRACE_USE_PTHREAD || defined TRACE_USE_FORK
    extern void __attribute__((aligned(4096))) *_trace_ptr;
    extern __attribute__((aligned(4096))) unsigned char *restrict _trace_buf;
#else
    extern unsigned char _trace_buf[TRACE_BUF_SIZE];
#endif

// trace position
#ifdef TRACE_USE_RINGBUFFER
    // pos++ should overflow to 0 exactly at TRACE_BUF_SIZE
    // therefore 16 bit short for pos and 1<<16 for TRACE_BUF_SIZE
    extern unsigned short _trace_buf_pos;
#else
    extern int _trace_buf_pos;
#endif

// trace ie byte
#ifndef BYTE_TRACE
    extern unsigned char _trace_ie_byte;
#endif

// write trace to disk
#ifndef TRACE_USE_RINGBUFFER
    // no disk-writing for ringbuffers
    extern void _trace_write(const void *buf);
    #ifndef EFFICIENT_TEXT_TRACE
        extern void _trace_write_text(const void *buf, unsigned long count);
    #endif
#endif

#endif //SRC_TRACER_TRACE_BUF_H
