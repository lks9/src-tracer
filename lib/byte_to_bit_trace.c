#include <src_tracer/_after_instrument.h>

#include <unistd.h>
#include <stdbool.h>

static unsigned char inbuf[4096];
static unsigned char outbuf[4096];
static int outpos = 0;

static void put_out(unsigned char c) {
    outbuf[outpos++] = c;
    if (outpos == 4096) {
        write(1, outbuf, 4096);
        outpos = 0;
    }
}

int main (void) {
    ssize_t len = read(0, inbuf, 4096);
    int skip = 0;
    int ie_count = 0;
    unsigned char ie_byte = _TRACE_SET_IE;
    for (int i = 0; true; i++) {
        if (i == len) {
            len = read(0, inbuf, 4096);
            if (len <= 0) {
                write(1, outbuf, outpos);
                return 0;
            }
            i = -1;
            continue;
        }
        unsigned char b = inbuf[i];
        if (skip > 0) {
            skip--;
            put_out(b);
            continue;
        }
        if (b == 'T' || b == 'N') {
            ie_byte |= (b == 'T') << ie_count;
            ie_count += 1;
            if (ie_count == 6) {
                put_out(ie_byte | (1 << 6));
                ie_byte = _TRACE_SET_IE;
                ie_count = 0;
            }
            continue;
        }
        if (ie_count > 0) {
            put_out(ie_byte | 1 << ie_count);
            ie_byte = _TRACE_SET_IE;
            ie_count = 0;
        }
        switch(b & _TRACE_TEST_OTHER) {
            case _TRACE_SET_FUNC_4:
                break;
            case _TRACE_SET_ELEM_AO:
                if (b == 'E') {
                    put_out(b);
                    write(1, outbuf, outpos);
                    while(read(0, inbuf, 4096) > 0);
                    return 0;
                }
                break;
            case _TRACE_SET_ELEM_PZ:
                break;
            case _TRACE_SET_FUNC_12:
                skip = 1;
                break;
            case _TRACE_SET_FUNC_20:
                skip = 2;
                break;
            case _TRACE_SET_FUNC_28:
                skip = 3;
                break;
            case _TRACE_SET_FUNC_32:
                skip = 4;
                break;
            case _TRACE_SET_DATA:
                skip = b & _TRACE_TEST_LEN_BYTECOUNT;
                break;
            default:
                break;
        }
        put_out(b);
    }
    return 0;
}
