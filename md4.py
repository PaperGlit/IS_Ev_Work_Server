import struct


class MD4:
    mask = 0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, msg=None):
        if msg is None:
            msg = b""

        self.msg = msg

        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)

        self._process([msg[i : i + 64] for i in range(0, len(msg), 64)])

    def bytes(self):
        return struct.pack("<4L", *self.h)

    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            xi, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            x_i = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                k_i, s_i = n, x_i[n % 4]
                hn = h[i] + self._F(h[j], h[k], h[l]) + xi[k_i]
                h[i] = self._lrot(hn & self.mask, s_i)

            # Round 2.
            x_i = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                k_i, s_i = n % 4 * 4 + n // 4, x_i[n % 4]
                hn = h[i] + self._G(h[j], h[k], h[l]) + xi[k_i] + 0x5A827999
                h[i] = self._lrot(hn & self.mask, s_i)

            # Round 3.
            x_i = [3, 9, 11, 15]
            ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                k_i, s_i = ki[n], x_i[n % 4]
                hn = h[i] + self._H(h[j], h[k], h[l]) + xi[k_i] + 0x6ED9EBA1
                h[i] = self._lrot(hn & self.mask, s_i)

            self.h = [((v + n) & self.mask) for v, n in zip(self.h, h)]

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)
    _lrot = lambda self, x, n: (x << n) | (x >> (32 - n))