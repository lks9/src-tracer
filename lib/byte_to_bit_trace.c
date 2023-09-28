#include <src_tracer/_after_instrument.h>

#include <unistd.h>
#include <stdbool.h>

char inbuf[4096];
char outbuf[4096];
int outpos = 0;

static void put_out(char c) {
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
    char ie_byte = _TRACE_SET_IE;
    for (int i = 0; true; i++) {
        if (i == len) {
            len = read(0, inbuf, 4096);
            i = 0;
            continue;
        }
        if (skip > 0) {
            skip--;
            put_out(inbuf[i]);
            continue;
        }
        if (inbuf[i] == 'T' || inbuf[i] == 'N') {
            ie_byte = (inbuf[i] == 'T') << ie_count;
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
        switch(inbuf[i] & _TRACE_TEST_OTHER) {
            case _TRACE_SET_FUNC_4:
                break;
            case _TRACE_SET_ELEM_AO:
                if (inbuf[i] == 'E') {
                    put_out(inbuf[i]);
                    write(1, outbuf, outpos);
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
                skip = inbuf[i] & _TRACE_TEST_LEN_BYTECOUNT;
                break;
            default:
                break;
        }
        put_out(inbuf[i]);
    }
    return 0;
}
