import mmap
import os
import re

# compact trace

TEST_IE          = 0b10000000
PUT_IE           = 0b10000000

TEST_FUNC_DATA   = 0b10001000
PUT_FUNC         = 0b00000000
PUT_DATA         = 0b00001000

TEST_LEN         = 0b11111000

PUT_FUNC_END     = 0b00000000
PUT_FUNC_LEN_8   = 0b00010000
PUT_FUNC_LEN_16  = 0b00100000
PUT_FUNC_LEN_32  = 0b00110000
PUT_FUNC_LEN_24  = 0b01000000
PUT_FUNC_RETURN  = 0b01010000
PUT_FUNC_ANON    = 0b01100000
PUT_FUNC_reserved= 0b01110000

PUT_LEN_0        = 0b00001000
PUT_LEN_8        = 0b00011000
PUT_LEN_16       = 0b00101000
PUT_LEN_32       = 0b00111000
PUT_LEN_64       = 0b01001000
PUT_LEN_reserved = 0b01011000
PUT_LEN_PREFIX   = 0b01101000
PUT_LEN_STRING   = 0b01111000

TEST_IE_COUNT    = 0b10000111

bit_length = {
    PUT_LEN_0: 0,
    PUT_LEN_8: 8,
    PUT_LEN_16: 16,
    PUT_LEN_32: 32,
    PUT_LEN_64: 64,

    PUT_FUNC_END: 0,
    PUT_FUNC_RETURN: 0,
    PUT_FUNC_ANON: 0,
    PUT_FUNC_LEN_8: 8,
    PUT_FUNC_LEN_16: 16,
    PUT_FUNC_LEN_24: 32,
    PUT_FUNC_LEN_32: 32,
}

byte_length = {
    PUT_LEN_0: 0,
    PUT_LEN_8: 1,
    PUT_LEN_16: 2,
    PUT_LEN_32: 4,
    PUT_LEN_64: 8,

    PUT_FUNC_END: 0,
    PUT_FUNC_RETURN: 0,
    PUT_FUNC_ANON: 0,
    PUT_FUNC_LEN_8: 1,
    PUT_FUNC_LEN_16: 2,
    PUT_FUNC_LEN_24: 3,
    PUT_FUNC_LEN_32: 4,
}

# compressable trace with _...

_TEST_DATA          = 0b11110000
_SET_DATA           = 0b11110000
_TEST_LEN           = 0b11111111
_SET_LEN_reserved0  = 0b11110000
_SET_LEN_reserved1  = 0b11110001
_SET_LEN_8          = 0b11110011
_SET_LEN_16         = 0b11110101
_SET_LEN_32         = 0b11110111
_SET_LEN_64         = 0b11111001
_SET_LEN_reserved2  = 0b11111011
_SET_LEN_PREFIX     = 0b11111101
_SET_LEN_reserved3  = 0b11111110
_SET_LEN_reserved4  = 0b11111111

_TEST_FUNC_6        = 0b11000000
_SET_FUNC_6         = 0b00000000
_TEST_FUNC_14       = 0b11000000
_SET_FUNC_14        = 0b10000000
_TEST_FUNC_20       = 0b11110000
_SET_FUNC_20        = 0b11000000
_TEST_FUNC_28       = 0b11110000
_SET_FUNC_28        = 0b11100000
_TEST_FUNC_36       = 0b11110000
_SET_FUNC_36        = 0b11010000

def letter(b, count=0):
    if b & TEST_IE == PUT_IE:
        if b & (1 << count):
            return 'T'
        else:
            return 'N'
    elif b & TEST_FUNC_DATA == PUT_DATA:
        l = b & TEST_LEN
        if l == PUT_LEN_STRING:
            return 'B'
        elif l != PUT_LEN_reserved:
            return 'D'
    elif b & TEST_FUNC_DATA == PUT_FUNC:
        l = b & TEST_LEN
        if l == PUT_FUNC_END:
            return 'E'
        elif l == PUT_FUNC_RETURN:
            return 'R'
        elif l == PUT_FUNC_ANON:
            return 'A'
        elif l != PUT_FUNC_reserved:
            return 'F'
    raise ValueError(f"There is no letter for {bin(b)}")


def to_number(bs):
    return int.from_bytes(bs, "little")


class TraceElem:
    def __init__(self, letter, bs, pos=None, ie_pos=None, big=False):
        self.letter = letter
        self.bs = bs
        self.pos = pos
        self.ie_pos = ie_pos
        self.big = big

    def __str__(self):
        return self.pretty(show_ie_pos=True)

    def pretty(self, show_pos=True, show_ie_pos=False, name=None):
        res = f"{self.letter}"
        if letter in ('S', 'B'):
            res += f'"{self.bs.decode()}"'
        elif self.bs != b'':
            if self.big:
                num = int.from_bytes(self.bs, "big")
            else:
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
    def from_file(filename, seek_bytes=0, seek_elems=0, count_bytes=-1, count_elems=1):
        """
        Read and and create a trace object from a file.
        If file ends with '.txt', a text trace is assumed, otherwise a compact binary trace.
        """
        # find the nearest multiple of pagesize from the seek_bytes,
        # due to mmap can only skip multiple of pagesize during setup
        offset = mmap.ALLOCATIONGRANULARITY * (seek_bytes // mmap.ALLOCATIONGRANULARITY)
        # start byte from the start of trace that exclude the first nearest multiple of pagesize
        seek_in_page = seek_bytes - offset
        size = os.stat(filename).st_size

        if filename[-4:] == '.txt':
            with open(filename, 'r') as f:
                trace = mmap.mmap(f.fileno(), size - offset, access=mmap.ACCESS_READ, offset = offset)
                if count_bytes >= 0:
                    offset_tail = mmap.ALLOCATIONGRANULARITY * ((seek_bytes + count_bytes) // mmap.ALLOCATIONGRANULARITY)
                    tail_seek_in_page = seek_bytes + count_bytes - offset_tail
                    trace_tail = mmap.mmap(f.fileno(), size - offset_tail, access=mmap.ACCESS_READ, offset=offset_tail)
                else:
                    trace_tail = b""
                    tail_seek_in_page = 0
                    count_elems = 0
            return TraceText(trace, seek_elems, count_elems, trace_tail, seek_in_page, tail_seek_in_page)
        elif filename[-7:] == '.ctrace':
            with open(filename, 'rb') as f:
                trace = mmap.mmap(f.fileno(), size - offset, access=mmap.ACCESS_READ, offset=offset)
                if count_bytes < 0:
                    count_bytes = len(trace)
                    count_elems = 0
            return TraceCompressable(trace, count_bytes, count_elems, seek_elems, seek_in_page)
        else:
            with open(filename, 'rb') as f:
                trace = mmap.mmap(f.fileno(), size - offset, access=mmap.ACCESS_READ, offset=offset)
                if count_bytes < 0:
                    count_bytes = len(trace)
                    count_elems = 0
            return TraceCompact(trace, count_bytes, count_elems, seek_elems, seek_in_page)

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
    def __init__(self, trace_str, seek_elems, count_elems, trace_tail, seek_in_page, tail_seek_in_page):
        self._trace_str = trace_str
        self._trace_tail = trace_tail
        self.seek_elems = seek_elems
        self.count_elems = count_elems
        self._seek_in_page = seek_in_page
        self._tail_seek_in_page = tail_seek_in_page

    def __iter__(self):
        """
        Iterate over the elements in the trace, respecting seek and count.
        """
        it = self.full_iter(self._trace_str, self._seek_in_page)
        for _ in range(self.seek_elems):
            next(it)
        for elem in it:
            yield elem
        count = self.count_elems
        for elem in self.full_iter(self._trace_tail, self._tail_seek_in_page):
            if count > 0:
                yield elem
                count -= 1
            else:
                break
        if count != 0:
            raise ValueError(f"Trace ended, could not yield {count} elements")

    @staticmethod
    def full_iter(trace_str, seek_in_page):
        """
        Iterate over all elements, ignoring seek and count of the object (seek_in_page is argument instead).
        """
        pat = re.compile(b"[A-Z][0-9a-z]*")

        # create a buffer in order to process big txt file
        buffer_size = mmap.ALLOCATIONGRANULARITY
        current_position = seek_in_page
        buffer = trace_str[current_position: current_position + buffer_size]
        while buffer != b'':
            for m in pat.finditer(buffer):
                letter = trace_str[current_position + m.start():current_position + m.start()+1].decode()
                hexstring = trace_str[current_position + m.start()+1:current_position + m.end()].decode()
                if hexstring == '':
                    yield TraceElem(letter, b'', current_position - seek_in_page + m.start())
                else:
                    if len(hexstring) % 2 == 1:
                        hexstring = "0" + hexstring
                    bs = bytearray.fromhex(hexstring)
                    yield TraceElem(letter, bs, current_position - seek_in_page + m.start(), big=True)
            current_position += buffer_size
            buffer = trace_str[current_position: current_position + buffer_size]

    # overwrite for complexity reasons
    def __str__(self):
        return self._trace_str

    def trace_close(self):
        self._trace_str.close()
        if self._trace_tail != b"":
            self._trace_tail.close()


class TraceCompressable(Trace):
    def __init__(self, trace_bytes, count_bytes, count_elems, seek_elems, seek_in_page):
        self._trace = trace_bytes
        self.seek_elems = seek_elems
        self.count_elems = count_elems
        self._seek_in_page = seek_in_page
        # self._count_bytes is assumed to be read only after init
        if count_bytes < 0:
            self._count_bytes = len(self._trace) - seek_in_page
        else:
            self._count_bytes = count_bytes

    def __iter__(self):
        """
        Iterate over the elements in the trace, respecting seek and count.
        """
        it = self.full_iter(self._trace, self._seek_in_page)
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
    def full_iter(trace, seek_in_page):
        """
        Iterate over all elements, ignoring seek and count of the object (seek_in_page is argument instead).
        """
        i = 0
        while i < len(trace) - seek_in_page:
            pos = i
            b = trace[seek_in_page + i]
            i += 1

            if chr(b) in ('T', 'N', 'A', 'R', 'E'):
                yield TraceElem(chr(b), b'', pos)
                continue

            elif chr(b) in ('S', 'B'):
                # 0 terminated string
                end = trace[seek_in_page+i:].index(0)
                bs = trace[seek_in_page+i:seek_in_page+i+end]
                i += end+1
                yield TraceElem(chr(b), bs, pos)
                continue

            elif b & _TEST_FUNC_6  == _SET_FUNC_6:
                bs = [b & 0x3f]
                yield TraceElem('F', bs, pos, big=True)
                continue
            elif b & _TEST_FUNC_14 == _SET_FUNC_14:
                start = seek_in_page+i
                i += 1
                end = seek_in_page+i
                bs = [b & 0x3f] + trace[start:end]
                yield TraceElem('F', bs, pos, big=True)
                continue
            elif b & _TEST_FUNC_20 == _SET_FUNC_20:
                start = seek_in_page+i
                i += 2
                end = seek_in_page+i
                bs = [b & 0xf] + trace[start:end]
                yield TraceElem('F', bs, pos, big=True)
                continue
            elif b & _TEST_FUNC_28 == _SET_FUNC_28:
                start = seek_in_page+i
                i += 3
                end = seek_in_page+i
                bs = [b & 0xf] + trace[start:end]
                yield TraceElem('F', bs, pos, big=True)
                continue
            elif b & _TEST_FUNC_36 == _SET_FUNC_36:
                start = seek_in_page+i
                i += 4
                end = seek_in_page+i
                bs = [b & 0xf] + trace[start:end]
                yield TraceElem('F', bs, pos, big=True)
                continue

            if b & _TEST_DATA != _SET_DATA:
                raise ValueError(f"Could not match {b:x} in trace.")

            len_bits = b & _TEST_LEN
            if len_bits == _SET_LEN_8:
                length = 1
            elif len_bits == _SET_LEN_16:
                length = 2
            elif len_bits == _SET_LEN_32:
                length = 4
            elif len_bits == _SET_LEN_64:
                length = 8
            elif len_bits == _SET_LEN_PREFIX:
                length = trace[seek_in_page + i]
                i += 1
            bs = trace[seek_in_page + i:seek_in_page + i + length]
            i += length
            yield TraceElem('D', bs, pos)

    def trace_close(self):
        self._trace.close()


class TraceCompact(Trace):
    def __init__(self, trace_bytes, count_bytes, count_elems, seek_elems, seek_in_page):
        self._trace = trace_bytes
        self.seek_elems = seek_elems
        self.count_elems = count_elems
        self._seek_in_page = seek_in_page
        # self._count_bytes is assumed to be read only after init
        if count_bytes < 0:
            self._count_bytes = len(self._trace) - seek_in_page
        else:
            self._count_bytes = count_bytes

    def __iter__(self):
        """
        Iterate over the elements in the trace, respecting seek and count.
        """
        it = self.full_iter(self._trace, self._seek_in_page)
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
    def full_iter(trace, seek_in_page):
        """
        Iterate over all elements, ignoring seek and count of the object (seek_in_page is argument instead).
        """
        after_count = [[], [], [], [], [], [], [], []]
        i = 0
        last_pos = -1
        ie_pos = 0
        while i < len(trace) - seek_in_page:
            pos = i
            b = trace[seek_in_page + i]
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
            if len_bits == PUT_FUNC_RETURN:
                length = 0
            elif len_bits == PUT_LEN_STRING:
                m = re.match(rb'[^\0]*\0', trace[seek_in_page + i:])
                length = m.end()
            elif len_bits == PUT_LEN_PREFIX:
                length = trace[seek_in_page + i]
                i += 1
            else:
                length = byte_length[len_bits]
            bs = trace[seek_in_page + i:seek_in_page + i + length]
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
            elif b & TEST_LEN == PUT_FUNC_RETURN:
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

            if b & TEST_FUNC_DATA == PUT_FUNC:
                bs = self._trace[i:i+length]
                yield TraceElem(letter(b), bs, pos)

            i += length

    def trace_close(self):
        self._trace.close()
