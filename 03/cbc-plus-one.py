from random import random, randbytes

from Crypto.Cipher import AES
from Crypto.Util import Padding


def encrypt(m: bytes, cipher: any):
    return cipher.encrypt(m)


def encrypt_either(m1: bytes, m2: bytes, cipher: any):
    if random() < 0.5:
        return 0, encrypt(m1, cipher)
    return 1, encrypt(m2, cipher)


def xor(b1: bytes, b2: bytes):
    return bytes(a ^ b for (a, b) in zip(b1, b2))


def increment_iv(iv: bytes):
    tmp = int.from_bytes(iv, "big")
    tmp += 1
    return tmp.to_bytes(len(iv), "big")


def construct_payload(m: bytes, iv: bytes, iv_initial: bytes):
    tmp = m[:AES.block_size]
    tmp = xor(tmp, iv)
    tmp = xor(tmp, iv_initial)
    tmp += m[AES.block_size:]
    return tmp


def main():
    ok_counter = 0
    num_iterations = 3000

    for i in range(num_iterations):
        # Oracle stuff
        # Generate initial cipher instance
        key = randbytes(16)
        cipher = AES.new(key, AES.MODE_CBC)
        iv_initial = cipher.iv

        # Adversary stuff
        m0 = Padding.pad(randbytes(10), AES.block_size)
        m1 = Padding.pad(randbytes(10), AES.block_size)
        assert len(m0) == len(m1)

        bit, c = encrypt_either(m0, m1, cipher)
        # print(c)

        # First iteration
        # Increment the IV
        iv = increment_iv(iv_initial)

        # Create a new cipher instance with the IV+1
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Construct the message payload
        m0_mod = construct_payload(m0, iv, iv_initial)

        # Query the payload from the oracle
        c0 = encrypt(m0_mod, cipher)
        # print(c0)

        # Second iteration (not needed)
        # iv = increment_iv(iv)
        # cipher = AES.new(key, AES.MODE_CBC, iv)
        # m1_mod = construct_payload(m1, iv, iv_initial)
        # c1 = encrypt(m1_mod, cipher)
        # print(c1)

        guess = 0 if c == c0 else 1

        if guess == bit:
            ok_counter += 1

    success_rate = ok_counter / num_iterations
    print("[+] Correct guesses:", ok_counter)
    print("[+] Number of runs:", num_iterations)
    print("[+] Success rate:", success_rate)

    if success_rate == 1.0:
        print("[+] This scheme clearly does not have IND-CPA")


if __name__ == "__main__":
    main()
