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

def to_number(bs):
    res = 0
    for i,b in enumerate(bs):
        res |= b << (i*8)
    return res

def trace_to_string(trace, sep1='', sep2=''):
    after_if_count = ["", "", "", "", "", "", "", ""]
    i = 0
    res = ""
    while (i < len(trace)):
        b = trace[i]
        i += 1
        is_ifel = b & TEST_IE == PUT_IE
        is_func = b & TEST_FUNC == PUT_FUNC
        is_data = b & TEST_DATA == PUT_DATA
        if is_ifel:
            for count in range(7):
                res += after_if_count[count]
                after_if_count[count] = ""
                if b & (1 << count):
                    res += "I"
                else:
                    res += "E"
        elif is_func or is_data:
            count = b & TEST_IE_COUNT
            len_bits = b & TEST_LEN
            if len_bits == PUT_LEN_0:
                length = 0
            elif len_bits == PUT_LEN_8:
                length = 1
            elif len_bits == PUT_LEN_16:
                length = 2
            elif len_bits == PUT_LEN_32:
                length = 4
            elif len_bits == PUT_LEN_64:
                length = 8
            else:
                print("Fehler")
            num = to_number(trace[i:i+length])
            i = i+length
            if is_func:
                elem = f'F{num:x}'
            else:
                elem = f'S{num:x}'
            after_if_count[count] += sep1 + elem + sep2
        else:
            raise
    return res

if __name__ == '__main__':
    import sys
    filename = sys.argv[1]

    with open(filename, "rb") as f:
        content = f.read()

    print(trace_to_string(content, '\n', ' '))
