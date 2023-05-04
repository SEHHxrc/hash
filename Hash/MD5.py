import struct


class MD5:
    def __init__(self):
        self.message = b''
        self.message_length = 0
        self.ciphertext = b''

        self.init_A = 0x67452301
        self.init_B = 0xEFCDAB89
        self.init_C = 0x98BADCFE
        self.init_D = 0x10325476

        self.block_size = 64

        self.A = self.init_A
        self.B = self.init_B
        self.C = self.init_C
        self.D = self.init_D
        '''
        self.A = 0x01234567
        self.B = 0x89ABCDEF
        self.C = 0xFEDCBA98
        self.D = 0x76543210
        '''

        self.t = [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
                  0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
                  0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
                  0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
                  0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
                  0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
                  0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
                  0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391]

        self.s = [[7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]]

        self.m = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                  1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
                  5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
                  0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]

    def filler(self):
        """
        fill the message, append filling data into another variable
        """
        # in implementations that only work with complete bytes: append 0x80 and pad with 0x00 bytes so that the
        # message length in bytes ≡ 56 (mod 64)
        self.ciphertext += b'\x80'
        self.ciphertext += b'\x00' * (56 - (self.message_length + 1) % self.block_size)
        # append length of message
        self.ciphertext += struct.pack(b'<Q', self.message_length * 8)

    @staticmethod
    def split(message: bytes, block_size) -> list[bytes]:
        """
        split the message by specified length
        :return: list[bytes]
        """
        M = []
        for i in range(0, len(message), block_size):
            M.append(struct.pack(b'>I', struct.unpack(b'<I', message[i:i+block_size])[0]))
        return M

    def change_pos(self):
        """
        exchange the value
        :return: None
        """
        a = self.A
        self.A = self.D
        self.D = self.C
        self.C = self.B
        self.B = a

    @staticmethod
    def f(x: int, y: int, z: int) -> int:
        return (x & y) | ((~x) & z)

    @staticmethod
    def g(x: int, y: int, z: int) -> int:
        return (x & z) | (y & (~z))

    @staticmethod
    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    @staticmethod
    def i(x: int, y: int, z: int) -> int:
        return y ^ (x | (~z))

    def rotate(self, m: bytes, s: int, t: int, func):
        mj = struct.unpack(b'>I', m)[0]
        temp = func(self.B, self.C, self.D) + self.A + mj + t
        temp = circuit_shift(temp, s)
        self.A = (self.B + temp) % (1 << 32)
        self.change_pos()

    def group_processing(self, message: list[bytes]):
        for j in range(64):
            if j < 16:
                self.rotate(message[self.m[j]], self.s[j//16][j % 4], self.t[j], self.f)
            elif j < 32:
                self.rotate(message[self.m[j]], self.s[j//16][j % 4], self.t[j], self.g)
            elif j < 48:
                self.rotate(message[self.m[j]], self.s[j//16][j % 4], self.t[j], self.h)
            else:
                self.rotate(message[self.m[j]], self.s[j//16][j % 4], self.t[j], self.i)

        self.A = (self.A + self.init_A) % (1 << 32)
        self.B = (self.B + self.init_B) % (1 << 32)
        self.C = (self.C + self.init_C) % (1 << 32)
        self.D = (self.D + self.init_D) % (1 << 32)

        # after each turn, init data must renew
        self.a = self.A
        self.b = self.B
        self.c = self.C
        self.d = self.D

    def update(self, message: bytes) -> None:
        """
        prioritise the first n blocks
        """
        self.message = message
        self.message_length = len(self.message)
        self.ciphertext = self.message[-(self.message_length % self.block_size):]
        m_part = self.split(self.message[:-(self.message_length % self.block_size)], 4)
        for i in range(0, len(m_part), 16):
            self.group_processing(m_part[i:i+16])

    def digest(self) -> bytes:
        """
        generate md5 value
        :return: bytes
        """
        self.filler()
        part_m = self.split(self.ciphertext, 4)
        for i in range(0, len(part_m), 16):
            self.group_processing(part_m[i:i+16])
        # little-endian
        return b''.join(struct.pack(b'<I', h) for h in [self.A, self.B, self.C, self.D])

    def hexadecimal(self) -> str:
        """
        generate md5 value in hex number
        :return: str
        """
        self.filler()
        part_m = self.split(self.ciphertext, 4)
        for i in range(0, len(part_m), 16):
            self.group_processing(part_m[i:i+16])
        result = ''
        # each block which is based on bytes must be reversed
        for i in [self.A, self.B, self.C, self.D]:
            mid = hex(i)[2:].zfill(8)
            for j in range(len(mid), 0, -2):
                result += mid[j-2:j]
        return result
    
    @staticmethod
    def circuit_shift(n: int, b: int):
        """left rotate a 32-bit integer n by b bits."""
        n &= 0xFFFFFFFF
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    @property
    def a(self) -> int:
        return self.init_A

    @property
    def b(self) -> int:
        return self.init_B

    @property
    def c(self) -> int:
        return self.init_C

    @property
    def d(self) -> int:
        return self.init_D

    @a.setter
    def a(self, a: int):
        self.init_A = a

    @b.setter
    def b(self, b: int):
        self.init_B = b

    @c.setter
    def c(self, c: int):
        self.init_C = c

    @d.setter
    def d(self, d: int):
        self.init_D = d

    @property
    def size(self) -> int:
        return self.block_size

    @size.setter
    def size(self, size: int):
        self.block_size = size
