/*
   src_tracer/trace_buf.h
   anything related to the trace buffer
*/
#ifndef SRC_TRACER_TRACE_BUF_H
#define SRC_TRACER_TRACE_BUF_H

#include "src_tracer/constants.h"

// trace buffer
#ifdef TRACE_USE_FORK
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
    #ifdef TRACE_IE_BYTE_REG
        register unsigned char _trace_ie_byte __asm__("r12");
    #else
        extern unsigned char _trace_ie_byte;
    #endif
#endif

// write trace to disk
#ifndef TRACE_USE_RINGBUFFER
    // no disk-writing for ringbuffers
    extern void _trace_write(void);
#endif

extern void _trace_pause(void);
extern void _trace_resume(void);
extern void _trace_in_fork_child(void);

#endif //SRC_TRACER_TRACE_BUF_H
