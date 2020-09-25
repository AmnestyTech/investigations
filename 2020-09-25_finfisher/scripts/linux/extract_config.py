import os
import sys
import argparse
import re
import struct

"""
Extract configuration of Linux FinSpy from an installer
author: Etienne Maynier, Amnesty Tech
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract configuration Linux Finspy sample')
    parser.add_argument('FILE', help='FinSpy sample for Linux')
    args = parser.parse_args()

    regex_cfg = re.compile(b'.[\x50-\x5f]\xa5\xaa\xca\xa6\x54\x5a.[\xa0-\xaf]\x5a\xa5\x0a')

    with open(args.FILE, 'rb') as f:
        data = f.read()

    if len(regex_cfg.findall(data)) < 5:
        print("This does not look like a FinSpy sample")
        sys.exit(-1)

    if not os.path.isdir('extracted'):
        os.mkdir('extracted')

    i = 1
    for cfg in regex_cfg.finditer(data):
        pos = cfg.span()[0]
        # Decrypt the first 4 bytes to get the length
        length = struct.unpack('I', bytearray([data[pos]^0xaa, data[pos+1]^0x5a, data[pos+2]^0xa5, data[pos+3]^0xaa]))[0]
        with open('extracted/{0:02d}.dat'.format(i), 'wb+') as f:
            f.write(data[pos:pos+length])
        print("Configuration file extracted {0:02d}.dat ({} bytes)".format(i, length))
        i += 1
