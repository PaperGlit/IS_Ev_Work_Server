import struct


class MD4:
    s = [
        [3, 7, 11, 19],
        [3, 5, 9,  13],
        [3, 9, 11, 15]
    ]
    K = [0, 0x5A827999, 0x6ED9EBA1]

    def __init__(self):
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def left_rotate(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _padding(self, message):
        message = bytearray(message)
        orig_len_in_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
        message.append(0x80)
        while (len(message) * 8) % 512 != 448:
            message.append(0)
        message += orig_len_in_bits.to_bytes(8, 'little')
        return message

    def _process_chunk(self, chunk):
        X = list(struct.unpack('<16I', chunk))
        A, B, C, D = self.h

        # Process rounds
        for i in range(3):
            if i == 0:
                op, func = [0, 1, 2, 3], self.F
            elif i == 1:
                op, func = [0, 4, 8, 12], self.G
            else:
                op, func = [0, 2, 1, 3], self.H

            for j in range(16):
                k = (op[j % 4] + j * (1 + (i > 0))) % 16
                temp = A + func(B, C, D) + X[k] + self.K[i]
                A, B, C, D = D, self.left_rotate(temp & 0xFFFFFFFF, self.s[i][j % 4]), B, C

        # Update state
        self.h[0] = (self.h[0] + A) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + B) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + C) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + D) & 0xFFFFFFFF

    def update(self, message):
        message = self._padding(message.encode('utf-8'))
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])

    def hexdigest(self):
        return ''.join(f'{value:02x}' for value in struct.unpack('<4I', struct.pack('>4I', *self.h)))

    @classmethod
    def hash(cls, message):
        md4 = cls()
        md4.update(message)
        return md4.hexdigest()