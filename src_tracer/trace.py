import re

TEST_IE          = 0b10000000
SET_IE           = 0b10000000
TEST_IE_INIT     = 0b11111111
SET_IE_INIT      = 0b11111110

TEST_FUNC       = 0b11000000
SET_FUNC        = 0b00000000

TEST_OTHER      = 0b11110000
SET_FUNC_4      = 0b00000000
SET_FUNC_12     = 0b00010000
SET_FUNC_20     = 0b00100000
SET_FUNC_28     = 0b00110000
SET_ELEM_AO     = 0b01000000
SET_ELEM_PZ     = 0b01010000
SET_ELEM2_ao    = 0b01100000
SET_ELEM2_pz    = 0b01110000

TEST_LEN          = 0b00000111
SET_LEN_0         = 0b00000000
SET_LEN_8         = 0b00000001
SET_LEN_16        = 0b00000010
SET_LEN_32        = 0b00000011
SET_LEN_64        = 0b00000100
SET_LEN_PREFIX_res= 0b00000101
SET_LEN_STRING_res= 0b00000110
SET_LEN_BYTECOUNT = 0b00000111

TEST_IS_ELEM    = 0b11100000
SET_IS_ELEM     = 0b01000000

TEST_ELEM       = 0b11111111
SET_END         = ord('E')
SET_RETURN      = ord('R')
SET_RETURN_TAIL = ord('S')
SET_FUNC_ANON   = ord('A')
SET_TRY         = ord('T')
SET_PAUSE       = ord('P')
#/* FUNC_32 always comes with 4 bytes, a 32 bit function number! */
SET_FUNC_32     = ord('C')
#/* 'I' and 'O' could be used instead of
# * _TRACE_IE_BYTE_INIT for faster trace writing */
SET_IF          = ord('I')
SET_ELSE        = ord('O')
#/* 'F' is reserved, use _TRACE_SET_ELEM2_FORK */
SET_FORK_res    = ord('F')
#/* 'J' is reserved, use _TRACE_SET_ELEM2_CATCH */
SET_CATCH_res   = ord('J')
#/* 'D' is reserved, use _TRACE_SET_ELEM2_DATA */
SET_DATA_res    = ord('D')

#/* 'X' to '_' are reserved */
TEST_ELEM_res   = 0b11111000
SET_ELEM_res    = 0b01011000

TEST_IS_ELEM2   = 0b11100000
SET_IS_ELEM2    = 0b01100000

TEST_ELEM2      = 0b11111000
SET_ELEM2_FORK  = 0b01100000
SET_ELEM2_CATCH = 0b01101000
SET_ELEM2_DATA  = 0b01110000
SET_ELEM2_res   = 0b01111000


bit_length = {
    SET_LEN_0: 0,
    SET_LEN_8: 8,
    SET_LEN_16: 16,
    SET_LEN_32: 32,
    SET_LEN_64: 64,

    SET_FUNC_4: 4,
    SET_FUNC_12: 12,
    SET_FUNC_20: 20,
    SET_FUNC_28: 28,
    SET_FUNC_32: 32,
}

byte_length = {
    SET_LEN_0: 0,
    SET_LEN_8: 1,
    SET_LEN_16: 2,
    SET_LEN_32: 4,
    SET_LEN_64: 8,

    SET_FUNC_4: 0,
    SET_FUNC_12: 1,
    SET_FUNC_20: 2,
    SET_FUNC_28: 3,
    SET_FUNC_32: 4,
}

def letter(b, count=0):
    if b & TEST_IE == SET_IE:
        if b & (1 << count):
            return 'I'
        else:
            return 'O'
    elif b & TEST_FUNC == SET_FUNC:
        return 'C'
    elif b & TEST_IS_ELEM == SET_IS_ELEM:
        return chr(b)
    elif b & TEST_ELEM2 == SET_ELEM2_FORK:
        return 'F'
    elif b & TEST_ELEM2 == SET_ELEM2_CATCH:
        return 'J'
    elif b & TEST_ELEM2 == SET_ELEM2_DATA:
        return 'D'
    raise ValueError(f"There is no letter for {bin(b)}")


class TraceElem:
    def __init__(self, letter, bs, pos=None, ie_pos=None, endian="little"):
        self.letter = letter
        self.bs = bs
        self.pos = pos
        self.ie_pos = ie_pos
        self.endian = endian

    def __str__(self):
        return self.pretty(show_ie_pos=True)

    @property
    def num(self):
        if self.bs == b'':
            return 0
        return int.from_bytes(self.bs, self.endian)

    def pretty(self, show_pos=True, show_ie_pos=False, name=None):
        res = f"{self.letter}"
        if self.bs != b'':
            num = int.from_bytes(self.bs, self.endian)
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
        if filename[-4:] == '.txt':
            with open(filename, 'r') as f:
                f.seek(seek_bytes)
                trace_str = f.read(count_bytes)
                if count_bytes >= 0:
                    trace_tail = f.read()
                else:
                    trace_tail = ""
                    count_elems = 0
            return TraceText(trace_str, seek_elems=seek_elems, count_elems=count_elems, trace_tail=trace_tail)
        elif filename[-4:] == '.zst':
            raise ValueError("Uncompress trace file first! Use: zstd -d")
        else:
            with open(filename, 'rb') as f:
                f.seek(seek_bytes)
                trace_bytes = f.read()
                if count_bytes < 0:
                    count_bytes = len(trace_bytes)
                    count_elems = 0
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
            if elem.letter in ('C', 'A'):
                yield elem


class TraceText(Trace):
    def __init__(self, trace_str, seek_elems, count_elems, trace_tail):
        self._trace = trace_str
        self._trace_tail = trace_tail
        self.seek_elems = seek_elems
        self.count_elems = count_elems

    def __iter__(self):
        """
        Iterate over the elements in the trace, respecting seek and count.
        """
        it = self.full_iter(self._trace)
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
        return self._trace


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
            elif elem.pos < self._count_bytes:
                yield elem
            elif count > 0:
                yield elem
                count -= 1
            else:
                break
            if elem.letter == 'E':
                break
        if count != 0:
            raise ValueError(f"Trace ended, could not yield {count} elements")

    @staticmethod
    def full_iter(trace):
        """
        Iterate over all elements, ignoring seek and count.
        """
        i = 0
        while i < len(trace):
            pos = i
            b = trace[i]
            i += 1

            if b & TEST_IE == SET_IE:
                count = 7
                ie_pos = 0
                while b & (1 << count):
                    count -= 1
                count -= 1
                while 0 <= count:
                    yield TraceElem(letter(b, count), b'', pos, ie_pos)
                    ie_pos += 1
                    count -= 1
                # done with ie
                continue

            endian = "little"
            if b & TEST_IS_ELEM2 == SET_IS_ELEM2:
                length = byte_length[b & TEST_LEN]
                bs = trace[i:i+length]
            elif b & TEST_IS_ELEM == SET_IS_ELEM:
                if b == SET_FUNC_32:
                    # function number
                    endian = "big"
                    length = 4
                    bs = trace[i:i+length]
                else:
                    length = 0
                    bs = b''
            elif b == 0:
                # skip 0
                continue
            else:
                # function number
                endian = "big"
                length = byte_length[b & TEST_OTHER]
                bs = (b &~ TEST_OTHER).to_bytes(1, "big") + trace[i:i+length]

            i += length
            yield TraceElem(letter(b), bs, pos, endian=endian)

    def function_iter(self):
        i = 0
        while i < len(self._trace):
            b = self._trace[i]
            pos = i
            i += 1
            if b & TEST_IE == SET_IE:
                continue
            elif b & TEST_IS_ELEM == SET_IS_ELEM:
                if b == SET_FUNC_32:
                    # function number
                    length = 4
                    bs = self._trace[i:i+length]
                    yield TraceElem(letter(b), bs, pos, endian="big")
                else:
                    continue
            elif b & TEST_IS_ELEM2 == SET_IS_ELEM2:
                length = byte_length[b & TEST_LEN]
            else:
                # function number
                length = byte_length[b & TEST_OTHER]
                bs = (b &~ TEST_OTHER).to_bytes(1, "big") + self._trace[i:i+length]
                yield TraceElem(letter(b), bs, pos, endian="big")

            i += length
