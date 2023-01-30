extern void _cflow_write(const void* buf, int count);

extern void _cflow_open(const char *fname);
extern void _cflow_close(void);

extern int _cflow_if_count;
extern unsigned char _cflow_if_byte;

#define _TEST_IE            0b10000000
 #define _PUT_IE            0b10000000
#define _TEST_FUNC          0b10001000
 #define _PUT_FUNC          0b00000000
#define _TEST_DATA          0b10001000
 #define _PUT_DATA          0b00001000
#define _TEST_LEN           0b11110000
 #define _PUT_LEN_0         0b00000000
 #define _PUT_LEN_8         0b00010000
 #define _PUT_LEN_16        0b00100000
 #define _PUT_LEN_32        0b00110000
 #define _PUT_LEN_64        0b01000000
 #define _PUT_LEN_reserved  0b01010000
 #define _PUT_LEN_PREFIX    0b01100000
 #define _PUT_LEN_STRING    0b01110000
#define _TEST_IE_COUNT      0b10000111

#define _CFLOW_PUT(c) \
    _cflow_write(&c, 1)

#define _CFLOW_PUT_IE(if_true) ;{ \
    _cflow_if_byte |= if_true << _cflow_if_count; \
    _cflow_if_count += 1; \
    if (_cflow_if_count == 7) { \
        _CFLOW_PUT(_cflow_if_byte); \
        _cflow_if_count = 0; \
        _cflow_if_byte = _PUT_IE; \
    } \
}

#define _CFLOW_PUT_NUM(type, num) ;{ \
    unsigned long long n = num; \
    int count; \
    unsigned char buf[9]; \
    buf[0] = type; \
    buf[0] |= _cflow_if_count; \
    if (n == 0) { \
        buf[0] |= _PUT_LEN_0; \
        count = 0; \
    } else if (n == (n & 0xff)) { \
        buf[0] |= _PUT_LEN_8; \
        count = 1; \
    } else if (n == (n & 0xffff)) { \
        buf[0] |= _PUT_LEN_16; \
        count = 2; \
    } else if (n == (n & 0xffffffff)) { \
        buf[0] |= _PUT_LEN_32; \
        count = 4; \
    } else { \
        buf[0] |= _PUT_LEN_64; \
        count = 8; \
    } \
    buf[1] = (n << 0) & 0xff; \
    buf[2] = (n << 8) & 0xff; \
    buf[3] = (n << 16) & 0xff; \
    buf[4] = (n << 24) & 0xff; \
    buf[5] = (n << 32) & 0xff; \
    buf[6] = (n << 40) & 0xff; \
    buf[7] = (n << 48) & 0xff; \
    buf[8] = (n << 56) & 0xff; \
    _cflow_write(buf, count+1); \
}

// same as the macro version
// but returns num
// can be used inside switch conditions
extern unsigned int _cflow_put_num(char c, unsigned int num);


#define _IF                 _CFLOW_PUT_IE(1)
#define _ELSE               _CFLOW_PUT_IE(0)
#define _FUNC(num)          _CFLOW_PUT_NUM(_PUT_FUNC, num)
// non-macro version for switch
#define _SWITCH(num)        _cflow_put_num(_PUT_DATA, num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _CFLOW_PUT_IE(1)
#define _LOOP_END(id)       _CFLOW_PUT_IE(0)

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    _cflow_open(fname); \
    int retval = main_original(argc, argv); \
    _cflow_close(); \
    return retval; \
}
