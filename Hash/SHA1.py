from src.Util.number import circuit_shift
import struct


class SHA1:
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    def __init__(self):
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0

        self.digest_size = 20
        self.block_size = 64

        self.unprocessed = b''
        self.message_byte_length = 0

    def process_chunk(self, chunk):
        """Process a chunk of data and return the new digest variables."""
        assert len(chunk) == 64

        w = [0] * 80

        # Break chunk into sixteen 4-byte big-endian words w[i]
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

        # extend the sixteen 4-byte words into eighty 4-byte words
        for i in range(16, 80):
            w[i] = circuit_shift(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4

        for i in range(80):
            f, k = None, None
            if i < 20:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((circuit_shift(a, 5) + f + e + k + w[i]) & (1 << 32) - 1,
                             a, circuit_shift(b, 30), c, d)

        self.h0 = (self.h0 + a) & (1 << 32) - 1
        self.h1 = (self.h1 + b) & (1 << 32) - 1
        self.h2 = (self.h2 + c) & (1 << 32) - 1
        self.h3 = (self.h3 + d) & (1 << 32) - 1
        self.h4 = (self.h4 + e) & (1 << 32) - 1

    def filler(self):
        """
        fill the message
        :return: bytes
        """
        self.unprocessed += b'\x80'
        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        self.unprocessed += b'\x00' * ((56 - (self.message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = self.message_byte_length * 8
        self.unprocessed += struct.pack(b'>Q', message_bit_length)

    @staticmethod
    def split(message: bytes, block_size) -> list[bytes]:
        """
        split the message by specified length
        :return: list[bytes]
        """
        M = []
        for i in range(0, len(message), block_size):
            M.append(message[i:i+block_size])
        return M

    def update(self, message: bytes):
        """
        update the current digest
        """
        self.message_byte_length = len(message)
        self.unprocessed = message[-(self.message_byte_length % self.block_size):]
        chunks = self.split(message[:-(self.message_byte_length % self.block_size)], self.block_size)

        for chunk in chunks:
            self.process_chunk(chunk)

    def digest(self):
        """generate the final hash value (big-endian) as a bytes object"""
        self.produce_digest()
        return b''.join(struct.pack(b'>I', h) for h in [self.h0, self.h1, self.h2, self.h3, self.h4])

    def hexadecimal(self):
        """generate the final hash value (big-endian) as a hex string"""
        self.produce_digest()
        return '%08x%08x%08x%08x%08x' % (self.h0, self.h1, self.h2, self.h3, self.h4)

    def produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        self.filler()

        # process the final chunk
        # in this case, the length of the message is either 64 or 128 bytes.
        self.process_chunk(self.unprocessed[:64])
        if len(self.unprocessed) == 64:
            return
        self.process_chunk(self.unprocessed[64:])
