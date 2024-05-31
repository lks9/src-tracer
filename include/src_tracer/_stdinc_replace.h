/*
   src_tracer/_stdinc_replace.h
   replace any standard libray headers we can't include when already pre-processed
*/
#ifndef SRC_TRACER_STDINC_REPLACE_H
#define SRC_TRACER_STDINC_REPLACE_H

// stdbool.h
#ifdef __cplusplus
    #define my_bool bool
#else
    // bool is available in C++ but not in C without stdbool.h
    #define my_bool _Bool
#endif

#endif // SRC_TRACER_STDINC_REPLACE_H
