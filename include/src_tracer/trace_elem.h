/*
   src_tracer/trace_elem.h
   definitions for the trace element format
*/
#ifndef SRC_TRACER_TRACE_ELEM_H
#define SRC_TRACER_TRACE_ELEM_H

#include "src_tracer/constants.h"

#ifndef BYTE_TRACE
#define _TRACE_TEST_IE              0b10000000
 #define _TRACE_SET_IE              0b10000000

#define _TRACE_TEST_IE_INIT         0b11111111
 #define _TRACE_SET_IE_INIT         0b11111110
#endif // not BYTE_TRACE

#define _TRACE_TEST_OTHER           0b11110000
 #define _TRACE_SET_FUNC_4          0b00000000
 #define _TRACE_SET_FUNC_12         0b00010000
 #define _TRACE_SET_FUNC_20         0b00100000
 #define _TRACE_SET_FUNC_28         0b00110000
 #define _TRACE_SET_ELEM_AO         0b01000000
 #define _TRACE_SET_ELEM_PZ         0b01010000
 #define _TRACE_SET_ELEM2_ao        0b01100000
 #define _TRACE_SET_ELEM2_pz        0b01110000

#define _TRACE_TEST_LEN             0b00000111
 #define _TRACE_SET_LEN_0           0b00000000
 #define _TRACE_SET_LEN_8           0b00000001
 #define _TRACE_SET_LEN_16          0b00000010
 #define _TRACE_SET_LEN_32          0b00000011
 #define _TRACE_SET_LEN_64          0b00000100
 #define _TRACE_SET_LEN_PREFIX_res  0b00000101
 #define _TRACE_SET_LEN_STRING_res  0b00000110
 #define _TRACE_SET_LEN_BYTECOUNT   0b00000111

#define _TRACE_TEST_IS_ELEM         0b11100000
 #define _TRACE_SET_IS_ELEM         0b01000000

#define _TRACE_TEST_ELEM            0b11111111
 #define _TRACE_SET_END             'E'
 #define _TRACE_SET_RETURN          'R'
 #define _TRACE_SET_RETURN_TAIL     'S'
 #define _TRACE_SET_FUNC_ANON       'A'
 #define _TRACE_SET_TRY             'T'
 #define _TRACE_SET_UNTRY           'U'
 #define _TRACE_SET_PAUSE           'P'
/* FUNC_32 always comes with 32 bit function number */
 #define _TRACE_SET_FUNC_32         'C'
/* 'I' and 'O' could be used instead of
 * _TRACE_IE_BYTE_INIT for faster trace writing */
 #define _TRACE_SET_IF              'I'
 #define _TRACE_SET_ELSE            'O'
/* 'F' is reserved, use _TRACE_SET_FORK */
 #define _TRACE_SET_FORK_reserved   'F'
/* 'J' is reserved, use _TRACE_SET_CATCH */
 #define _TRACE_SET_CATCH_reserved  'J'
/* 'D' is reserved, use _TRACE_SET_DATA */
 #define _TRACE_SET_DATA_reserved   'D'

/* 'X' to '_' are reserved */
#define _TRACE_TEST_ELEM_reserved   0b11111000
 #define _TRACE_SET_ELEM_reserved   0b01011000

#define _TRACE_TEST_IS_ELEM2        0b11100000
 #define _TRACE_SET_IS_ELEM2        0b01100000

#define _TRACE_TEST_ELEM2           0b11111000
 #define _TRACE_SET_FORK            0b01100000
 #define _TRACE_SET_CATCH           0b01101000
 #define _TRACE_SET_DATA            0b01110000
 #define _TRACE_SET_ELEM2_reserved  0b01111000


#endif // SRC_TRACER_TRACE_ELEM_H
