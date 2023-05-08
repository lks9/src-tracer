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
TEST_END         = 0b11111000
PUT_END          = 0b00000000
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


def letter(b, count=0):
    if b & TEST_IE == PUT_IE:
        if b & (1 << count):
            return 'T'
        else:
            return 'N'
    elif b & TEST_DATA == PUT_DATA:
        if b & TEST_LEN == PUT_LEN_STRING:
            return 'B'
        elif b & TEST_LEN != PUT_LEN_reserved:
            return 'D'
    elif b & TEST_FUNC == PUT_FUNC:
        if b & TEST_END == PUT_END:
            return 'E'
        elif b & TEST_RETURN == PUT_RETURN:
            return 'R'
        elif b & TEST_LEN == PUT_LEN_STRING:
            return 'S'
        elif b & TEST_LEN != PUT_LEN_reserved:
            return 'F'
    raise ValueError(f"There is no letter for {bin(b)}")


def to_number(bs):
    return int.from_bytes(bs, "little")


class TraceElem:
    def __init__(self, letter, bs, pos=None, ie_pos=None):
        self.letter = letter
        self.bs = bs
        self.pos = pos
        self.ie_pos = ie_pos

    def __str__(self):
        return self.pretty(show_ie_pos=True)

    def pretty(self, show_pos=True, show_ie_pos=False, name=None):
        res = f"{self.letter}"
        if self.bs != b'':
            num = int.from_bytes(self.bs, "little")
            res += f"{num:x}"
        if name is not None:
            res += f" {name}"
        if self.ie_pos is not None:
            if show_ie_pos:
                res += f" --count {self.pos} --count-elems {self.ie_pos}"
        elif self.pos is not None:
            if show_pos:
                res += f" --count {self.pos}"
        return res


class Trace:

    @staticmethod
    def from_file(filename, seek_bytes=0, seek_elems=0, count_bytes=-1, count_elems=0):
        """
        Read and and create a trace object from a file.
        If file ends with '.txt', a text trace is assumed, otherwise a compact binary trace.
        """
        if filename[-4:] == '.txt':
            with open(filename, 'r') as f:
                f.seek(seek_bytes)
                trace_str = f.read(count_bytes)
                if count_bytes >= 0:
                    trace_tail = f.read()
                else:
                    trace_tail = ""
            return TraceText(trace_str, seek_elems=seek_elems, count_elems=count_elems, trace_tail=trace_tail)
        else:
            with open(filename, 'rb') as f:
                f.seek(seek_bytes)
                trace_bytes = f.read()
                if count_bytes < 0:
                    count_bytes = len(trace_bytes)
            return TraceCompact(trace_bytes, seek_elems=seek_elems, count_bytes=count_bytes, count_elems=count_elems)

    def __str__(self):
        res = ''
        for elem in iter(self):
            # reverse the byte order from little endian to display as usual
            ba = bytearray(elem.bs)
            ba.reverse()
            hexstring = ba.hex()
            if re.match(r"0", hexstring):
                # remove a leading 0
                hexstring = hexstring[1:]
            res += elem.letter + hexstring
            if elem.letter == 'E':
                return res
        # normally, a trace should end with F0
        return res

    def function_iter(self):
        """
        Yield all function calls in a trace.
        """
        for elem in iter(self):
            if elem.letter in ('F', 'S'):
                yield elem


class TraceText(Trace):
    def __init__(self, trace_str, seek_elems, count_elems, trace_tail):
        self._trace_str = trace_str
        self._trace_tail = trace_tail
        self.seek_elems = seek_elems
        self.count_elems = count_elems

    def __iter__(self):
        """
        Iterate over the elements in the trace, respecting seek and count.
        """
        it = self.full_iter(self._trace_str)
        for _ in range(self.seek_elems):
            next(it)
        for elem in it:
            yield elem
        count = self.count_elems
        for elem in self.full_iter(self._trace_tail):
            if count > 0:
                yield elem
                count -= 1
            else:
                break
        if count != 0:
            raise ValueError(f"Trace ended, could not yield {count} elements")

    @staticmethod
    def full_iter(trace_str):
        """
        Iterate over all elements, ignoring seek and count.
        """
        for m in re.finditer(r"[A-Z][0-9a-z]*", trace_str):
            letter = trace_str[m.start():m.start()+1]
            hexstring = trace_str[m.start()+1:m.end()]
            if hexstring == '':
                yield TraceElem(letter, b'', m.start())
            else:
                if len(hexstring) % 2 == 1:
                    hexstring = "0" + hexstring
                # reverse the byte order to save as little endian
                ba = bytearray.fromhex(hexstring)
                ba.reverse()
                bs = bytes(ba)
                yield TraceElem(letter, bs, m.start())

    # overwrite for complexity reasons
    def __str__(self):
        return self._trace_str


class TraceCompact(Trace):
    def __init__(self, trace_bytes, count_bytes, count_elems, seek_elems):
        self._trace = trace_bytes
        self.seek_elems = seek_elems
        self.count_elems = count_elems
        # self._count_bytes is assumed to be read only after init
        if count_bytes < 0:
            self._count_bytes = len(self._trace)
        else:
            self._count_bytes = count_bytes

    def __iter__(self):
        """
        Iterate over the elements in the trace, respecting seek and count.
        """
        it = self.full_iter(self._trace)
        for _ in range(self.seek_elems):
            next(it)
        count = self.count_elems
        for elem in it:
            if elem.pos < 0:
                continue
            elif elem.letter == 'E':
                break
            elif elem.pos < self._count_bytes:
                yield elem
            elif count > 0:
                yield elem
                count -= 1
            else:
                break
        if count != 0:
            raise ValueError(f"Trace ended, could not yield {count} elements")

    @staticmethod
    def full_iter(trace):
        """
        Iterate over all elements, ignoring seek and count.
        """
        after_count = [[], [], [], [], [], [], [], []]
        i = 0
        last_pos = -1
        ie_pos = 0
        while i < len(trace):
            pos = i
            b = trace[i]
            i += 1

            if b & TEST_IE == PUT_IE:
                for count in range(7):
                    for elem in after_count[count]:
                        ie_pos = 1
                        yield elem
                        last_pos = elem.pos
                    after_count[count] = []
                    # yield 'T'/'N'
                    ie_pos += 1
                    yield TraceElem(letter(b, count), b'', last_pos, ie_pos)
                continue

            len_bits = b & TEST_LEN
            if b & TEST_RETURN == PUT_RETURN:
                length = 0
            elif len_bits == PUT_LEN_STRING:
                m = re.match(rb'[^\0]*\0', trace[i:])
                length = m.end()
            elif len_bits == PUT_LEN_PREFIX:
                length = trace[i]
                i += 1
            else:
                length = byte_length[len_bits]
            bs = trace[i:i+length]
            i += length
            count = b & TEST_IE_COUNT
            elem = TraceElem(letter(b), bs, pos)
            after_count[count].append(elem)

        # yield possibly remaining elements
        for elem in after_count[0]:
            yield elem

    def function_iter(self):
        i = 0
        while i < len(self._trace):
            b = self._trace[i]
            pos = i
            i += 1
            if b & TEST_IE == PUT_IE:
                continue
            elif b & TEST_RETURN == PUT_RETURN:
                continue

            len_bits = b & TEST_LEN
            if len_bits == PUT_LEN_STRING:
                m = re.match(rb'[^\0]*\0', self._trace[i:])
                length = m.end()
            elif len_bits == PUT_LEN_PREFIX:
                length = self._trace[i]
                i += 1
            else:
                length = byte_length[len_bits]

            if b & TEST_FUNC == PUT_FUNC:
                bs = self._trace[i:i+length]
                yield TraceElem(letter(b), bs, pos)

            i += length
