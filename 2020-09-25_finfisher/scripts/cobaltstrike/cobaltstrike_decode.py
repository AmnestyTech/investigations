import argparse
import struct
import sys

"""
Decrypt a Cobalt Strike encrypted beacon

Author: Etienne Maynier, Amnesty Tech
Date: March 2020
"""

def xor(a, b):
    return bytearray([a[0]^b[0], a[1]^b[1], a[2]^b[2], a[3]^b[3]])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decode an encoded Cobalt Strike beacon')
    parser.add_argument('PAYLOAD', help='an integer for the accumulator')
    args = parser.parse_args()

    with open(args.PAYLOAD, "rb") as f:
        data = f.read()

    # The base address of the sample change depending on the code
    ba = data.find(b"\xe8\xd4\xff\xff\xff")
    if ba == -1:
        ba = data.find(b"\xe8\xd0\xff\xff\xff")
        if ba == -1:
            print("Base Address not found")
            sys.exit(1)
    ba += 5

    key = data[ba:ba+4]
    print("Key : {}".format(key))
    size = struct.unpack("I", xor(key, data[ba+4:ba+8]))[0]
    print("Size : {}".format(size))

    res = bytearray()
    i = ba+8
    while i < (len(data) - ba - 8):
        d = data[i:i+4]
        res += xor(d, key)
        key = d
        i += 4

    if not res.startswith(b"MZ"):
        print("Invalid decoding, no PE header")

    with open("a.out", "wb+") as f:
        f.write(res)
    print("PE file extracted in a.out")
