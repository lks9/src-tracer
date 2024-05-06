/*
   src_tracer/trace_buf.h
   anything related to the trace buffer
*/
#ifndef SRC_TRACER_TRACE_BUF_H
#define SRC_TRACER_TRACE_BUF_H

#include "src_tracer/constants.h"

#ifndef BYTE_TRACE
    extern unsigned char _trace_ie_byte;
#endif

extern unsigned char _trace_buf[TRACE_BUF_SIZE];
#ifdef TRACE_USE_RINGBUFFER
    // pos++ should overflow to 0 exactly at TRACE_BUF_SIZE
    // therefore 16 bit short for pos and 1<<16 for TRACE_BUF_SIZE
    extern unsigned short _trace_buf_pos;
#else
    extern int _trace_buf_pos;
#endif

#ifndef TRACE_USE_RINGBUFFER
    // no disk-writing for ringbuffers
    extern void _trace_write(const void *buf);
    #ifndef EFFICIENT_TEXT_TRACE
        extern void _trace_write_text(const void *buf, unsigned long count);
    #endif
#endif

#endif //SRC_TRACER_TRACE_BUF_H
