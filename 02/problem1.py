from typing import Literal


def byte_length(i):
    return (i.bit_length() + 7) // 8


def xor_bytes(a: bytes, b: bytes, byteorder: Literal["little", "big"] = "big"):
    if len(a) != len(b):
        raise Exception("Inputs not of the same length")

    int_a = int.from_bytes(a, byteorder)
    int_b = int.from_bytes(b, byteorder)
    int_xor = int_a ^ int_b
    return int_xor.to_bytes(len(a), byteorder)


def split_bytes(b: bytes):
    return b[:len(b) // 2], b[len(b) // 2:]


def recover_words(xored: bytes, f_wordlist: str):
    wordlen = len(xored)

    with open(f_wordlist, "r") as f:
        # strip newlines and encode to get correct byte-length of word
        while base := f.readline().rstrip().encode():
            # we know the length of the encrypted word
            if len(base) != wordlen:
                continue
            res = xor_bytes(xored, base)

            with open(f_wordlist, "rb") as fp:
                # read the whole file in memory for fast search speed
                if not (res in fp.read()):
                    continue

                return base.decode(), res.decode()


def main():
    c = 0x4A5C45492449552A5A47534D35525F20
    c_bytes = c.to_bytes(byte_length(c), "big")
    # half the ciphertext
    a, b = split_bytes(c_bytes)

    # XOR both halves to get rid of the repeating key
    # since (a ^ k) ^ (b ^ k) = a ^ b
    xored = xor_bytes(a, b)

    # we brute force the word
    print("[+] Brute forcing the words.", "This may take a while...")
    m1, m2 = recover_words(xored, "wordlist.txt")

    # we can't recover the word order as we can recover
    # two separate keys that both give a different word order
    print(f"[+] Found `{m1}', `{m2}' as candidates")
    print(f"[+] The plaintext is: `{m1}{m2}' or `{m2}{m1}'")


if __name__ == "__main__":
    main()
