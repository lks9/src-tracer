#!/usr/bin/env python3


TEST_IE          = 0b10000000
PUT_IE           = 0b10000000
TEST_FUNC        = 0b10001000
PUT_FUNC         = 0b00000000
TEST_DATA        = 0b10001000
PUT_DATA         = 0b00001000
TEST_LEN         = 0b11110000
PUT_LEN_0        = 0b00000000
PUT_LEN_8        = 0b00010000
PUT_LEN_16       = 0b00100000
PUT_LEN_32       = 0b00110000
PUT_LEN_64       = 0b01000000
PUT_LEN_reserved = 0b01010000
PUT_LEN_PREFIX   = 0b01100000
PUT_LEN_STRING   = 0b01110000
TEST_IE_COUNT    = 0b10000111

bit_length = {
    PUT_LEN_0: 0,
    PUT_LEN_8: 8,
    PUT_LEN_16: 16,
    PUT_LEN_32: 32,
    PUT_LEN_64: 64,
}
byte_length = {
    PUT_LEN_0: 0,
    PUT_LEN_8: 1,
    PUT_LEN_16: 2,
    PUT_LEN_32: 4,
    PUT_LEN_64: 8,
}


def to_number(bs):
    res = 0
    for i, b in enumerate(bs):
        res |= b << (i*8)
    return res


def trace_to_string(trace, sep1='', sep2=''):
    if trace.isascii() and trace.isprintable():
        # simply return the trace if trace is not binary, but ascii
        return trace.decode('ascii')

    after_if_count = ["", "", "", "", "", "", "", ""]
    i = 0
    res = ""
    while i < len(trace):
        b = trace[i]
        i += 1
        is_ifel = b & TEST_IE == PUT_IE
        is_func = b & TEST_FUNC == PUT_FUNC
        is_data = b & TEST_DATA == PUT_DATA
        if is_ifel:
            for count in range(7):
                res += after_if_count[count]
                if res[-2:] == "F0":
                    # F0 marks the end of a trace...
                    return res
                after_if_count[count] = ""
                if b & (1 << count):
                    res += "T"
                else:
                    res += "N"
        elif is_func or is_data:
            count = b & TEST_IE_COUNT
            length = byte_length[b & TEST_LEN]
            num = to_number(trace[i:i+length])
            i = i+length
            if is_func:
                elem = f'F{num:x}'
            else:
                elem = f'S{num:x}'
            after_if_count[count] += sep1 + elem + sep2
        else:
            raise ValueError("This is not a trace string!")
    return res


if __name__ == '__main__':
    import sys
    filename = sys.argv[1]

    with open(filename, "rb") as f:
        content = f.read()

    print(trace_to_string(content))
