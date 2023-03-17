import re

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
TEST_RETURN      = 0b11111000
PUT_RETURN       = 0b01010000
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
    return int.from_bytes(bs, "little")


class Trace:
    @staticmethod
    def from_file(filename):
        if filename[-4:] == '.txt':
            with open(filename, 'r') as f:
                trace_str = f.read()
            return TraceText(trace_str)
        else:
            with open(filename, 'rb') as f:
                trace_bytes = f.read()
            return TraceCompact(trace_bytes)

    def __iter__(self):
        yield ('F', b'')

    def __str__(self):
        res = ''
        for (elem, bs) in iter(self):
            # reverse the byte order from little endian to display as usual
            ba = bytearray(bs)
            ba.reverse()
            hexstring = ba.hex()
            if re.match(r"0", hexstring):
                # remove a leading 0
                hexstring = hexstring[1:]
            res += elem + hexstring
            if elem == 'F' and bs == b'':
                return res
        # normally, a trace should end with F0
        return res


class TraceText(Trace):
    def __init__(self, trace_str):
        self._trace_str = trace_str

    def __iter__(self):
        for elemnum in re.findall(r"[A-Z][0-9a-z]*", self._trace_str):
            if elemnum[1:] == '':
                yield (elemnum[0], b'')
            else:
                hexstring = elemnum[1:]
                if len(hexstring) % 2 == 1:
                    hexstring = "0" + hexstring
                # reverse the byte order to save as little endian
                ba = bytearray.fromhex(hexstring)
                ba.reverse()
                bs = bytes(ba)
                yield (elemnum[0], bs)

    # overwrite for complexity reasons
    def __str__(self):
        return self._trace_str


class TraceCompact(Trace):
    def __init__(self, trace_bytes):
        self._trace = trace_bytes

    def __iter__(self):
        after_count = [[], [], [], [], [], [], [], []]
        i = 0
        while i < len(self._trace):
            b = self._trace[i]
            i += 1
            is_ifel = b & TEST_IE == PUT_IE
            is_func = b & TEST_FUNC == PUT_FUNC
            is_data = b & TEST_DATA == PUT_DATA
            if is_ifel:
                for count in range(7):
                    for elem in after_count[count]:
                        yield elem
                    after_count[count] = []
                    if b & (1 << count):
                        yield ('T', b'')
                    else:
                        yield ('N', b'')
            elif is_func or is_data:
                count = b & TEST_IE_COUNT
                len_bits = b & TEST_LEN
                is_ret = b & TEST_RETURN == PUT_RETURN
                if is_ret:
                    elem = ('R', b'')
                elif len_bits == PUT_LEN_STRING:
                    m = re.match(rb'[^\0]*\0', b)
                    length = m.end()
                    bs = self._trace[i:i+length]
                    i += length
                    if is_func:
                        elem = ('S', bs)
                    else:
                        elem = ('B', bs)
                else:
                    if len_bits == PUT_LEN_PREFIX:
                        length = self._trace[i]
                        i += 1
                    else:
                        length = byte_length[len_bits]
                    bs = self._trace[i:i+length]
                    i += length
                    if is_func:
                        elem = ('F', bs)
                    else:
                        elem = ('D', bs)
                after_count[count].append(elem)
            else:
                raise ValueError("These bytes are not in the trace format!")
        # yield possibly remaining elements
        for elem in after_count[0]:
            yield elem
