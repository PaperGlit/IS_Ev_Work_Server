import random
import math


class RSA:
    def __init__(self):
        self.public_key, self.private_key = self.generate_keys()

    @staticmethod
    def is_prime(n):
        if  n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def generate_pq(prev_value):
        while True:
            value = random.randint(2 ** 8, 2 ** 16)
            if RSA.is_prime(value) and value != prev_value:
                return value

    @staticmethod
    def generate_e(phi):
        while True:
            e = random.randint(2, phi)
            if math.gcd(e, phi) == 1:
                return e

    @staticmethod
    def generate_keys():
        p = RSA.generate_pq(0)
        q = RSA.generate_pq(p)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = RSA.generate_e(phi)
        d = pow(e, -1, phi)
        return (n, e), (n, d)

    def decrypt(self, message):
        n, d = self.private_key
        decrypted_message = ''.join([chr(pow(char, d, n)) for char in message])
        return decrypted_message

