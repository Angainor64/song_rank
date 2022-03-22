from typing import List, Final


# DEBUG,
active_loggers = ['DEBUG']
def eprint(level: str, *values: object, sep: str | None = ' ', end: str | None = '\n'):
    if level in active_loggers:
        for x in values:
            print(x, end=sep)
        print(end, sep='', end='')


class Word:  # TODO: Add checking that self.w == other.w for all operations
    @property
    def w(self) -> int:
        return self._w

    @property
    def data(self) -> str:
        return self._data

    def __init__(self, data: str, w: int, base: str = 'bin'):
        """
        :param data: the binary or hex representation of the word, as a string, without the 0b or 0x
        :param w: the intended length of data
        :param base: indicates the base of data (must be either 'hex' or bin')
        """
        self.w = w
        if base not in ['bin', 'hex']:
            raise NotImplementedError('Base must be "hex" or "bin"')
        if base == 'hex':
            data = bin(int(data, 16))[2:]
        self.data = data.rjust(w, '0')

    def __str__(self):
        return f'Word(data={self.data}, w={self.w})'

    def __int__(self):
        return int(self.data, 2)

    def __index__(self):
        return int(self.data, 2)

    def __and__(self, other) -> 'Word':
        if not isinstance(other, Word):
            raise NotImplementedError
        return Word(bin(int(self.data, 2) & int(other.data, 2))[2:], self.w)

    def __add__(self, other) -> 'Word':
        if not isinstance(other, Word):
            raise NotImplementedError
        return Word(bin((int(self.data, 2) + int(other.data, 2)) % (2 ** self.w))[2:], self.w)

    def __or__(self, other) -> 'Word':
        if not isinstance(other, Word):
            raise NotImplementedError
        return Word(bin(int(self.data, 2) | int(other.data, 2))[2:], self.w)

    def __xor__(self, other) -> 'Word':
        if not isinstance(other, Word):
            raise NotImplementedError
        return Word(bin(int(self.data, 2) ^ int(other.data, 2))[2:], self.w)

    def __lshift__(self, n: int) -> 'Word':
        if n >= self.w:
            raise ValueError('Cannot shift more bits than length of word')
        return Word(self.data[n:].ljust(self.w, '0'), self.w)

    def __rshift__(self, n: int) -> 'Word':
        if n >= self.w:
            raise ValueError('Cannot shift more bits than length of word')
        return Word(self.data[:self.w - n].rjust(self.w, '0'), self.w)

    def __invert__(self) -> 'Word':
        all_ones = 2 ** self.w - 1
        return Word(bin(all_ones ^ int(self.data))[2:], self.w)

    def rotl(self, n: int) -> 'Word':
        if n >= self.w:
            raise ValueError('Cannot shift more bits than length of word')
        return Word(self.data[n:] + self.data[self.w - n], self.w)

    def rotr(self, n: int) -> 'Word':
        if n >= self.w:
            raise ValueError('Cannot shift more bits than length of word')
        return Word(self.data[self.w - n] + self.data[n:], self.w)

    def shr(self, n: int) -> 'Word':
        return self >> n

    @w.setter
    def w(self, value: int):
        if value % 4:
            raise ValueError('w must be divisible by 4, otherwise Word is not representable by a hex number')
        if value < 1:
            raise ValueError('w must be greater than 0')
        self._w = value

    @data.setter
    def data(self, value: str):
        self._data = value


class SHA256:
    initial_hash_words = ['6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a',
                          '510e527f', '9b05688c', '1f83d9ab', '5be0cd19']
    initial_hash: Final[List[Word]] = [Word(word, 32, 'hex') for word in initial_hash_words]
    with open('SHA256_constants.txt', 'r') as f:
        K256 = [Word(x, 32, 'hex') for x in f.read().splitlines()]

    @classmethod
    def ch(cls, x: Word, y: Word, z: Word) -> Word:
        return (x & y) ^ (~x & z)

    @classmethod
    def maj(cls, x: Word, y: Word, z: Word) -> Word:
        return (x & y) ^ (x & z) ^ (y & z)

    @classmethod
    def upper_sigma_zero(cls, x: Word) -> Word:
        return x.rotr(2) ^ x.rotr(13) ^ x.rotr(22)

    @classmethod
    def upper_sigma_one(cls, x: Word) -> Word:
        return x.rotr(6) ^ x.rotr(11) ^ x.rotr(25)

    @classmethod
    def lower_sigma_zero(cls, x: Word) -> Word:
        return x.rotr(7) ^ x.rotr(18) ^ x.shr(3)

    @classmethod
    def lower_sigma_one(cls, x: Word) -> Word:
        return x.rotr(17) ^ x.rotr(19) ^ x.shr(10)

    @classmethod
    def make_bits(cls, message: str) -> str:
        """
        Turns an ASCII string to the binary representation using UTF-8 encoding

        :param message: The message, as a string. Ex: 'Hello, World!'
        :return: A non-separated representation of message in binary
        """
        return ''.join('{:08b}'.format(d) for d in bytearray(message, 'utf-8'))

    @classmethod
    def pad(cls, message: str) -> str:
        """
        Part of preprocessing for the SHA-256 algorithm

        :param message: binary representation of the message
        :return: padded message, ready for parsing
        """
        msg_len = len(message)
        if msg_len >= 2 ** 64:
            raise ValueError('Message is too long')
        k = (448 - (msg_len + 1)) % 512
        tail = bin(msg_len)[2:].rjust(64, '0')
        zero_pad = '0' * k
        eprint('DEBUG', f'{hex(int(f"{message}1{zero_pad}{tail}", 2)) = }')
        eprint('DEBUG', f'length after padding = {len(f"{message}1{zero_pad}{tail}")}')
        return f'{message}1{zero_pad}{tail}'

    @classmethod
    def parse(cls, message: str) -> List[List[Word]]:
        out = []
        for i in range(0, len(message), 512):
            block = message[i:i+512]
            out.append([Word(block[j:j + 32], 32) for j in range(0, 512, 32)])
        return out

    @classmethod
    def hash(cls, message: List[List[Word]]) -> str:
        spacer = ' ' * 8
        eprint('DEBUG', f' {spacer}A{spacer}B{spacer}C{spacer}D{spacer}E{spacer}F{spacer}G{spacer}H')
        hash_value = cls.initial_hash
        for i in range(len(message)):
            schedule = message[i].copy()
            for t in range(16, 64):
                schedule.append(cls.lower_sigma_one(schedule[t-2]) + schedule[t-7] +
                                cls.lower_sigma_zero(schedule[t-15] + schedule[t-16]))
            a, b, c, d, e, f, g, h = hash_value
            for t in range(64):
                t1 = h + cls.upper_sigma_one(e) + cls.ch(e, f, g) + cls.K256[t] + schedule[t]
                t2 = cls.upper_sigma_zero(a) + cls.maj(a, b, c)
                h = g
                g = f
                f = e
                e = d + t1
                d = c
                c = b
                b = a
                a = t1 + t2
                letters = [a, b, c, d, e, f, g, h]
                eprint('DEBUG', f't={str(t).rjust(2)}: {" ".join([hex(letter)[2:].upper() for letter in letters])}')
            for j in range(len(hash_value)):
                hash_value[j] = letters[j] + hash_value[j]
        return ''.join([hex(x)[2:] for x in hash_value])

    @classmethod
    def full_hashing(cls, message: str) -> str:
        return cls.hash(cls.parse(cls.pad(cls.make_bits(message))))


if __name__ == '__main__':
    full = SHA256.full_hashing('abc')
    print(f'{full = }')
    print(f'{len(full) = }')
    print(f'{str(full) = }')
