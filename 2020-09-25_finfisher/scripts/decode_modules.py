import sys
import os
import struct
import hashlib
import ctypes
import binascii
import argparse
from Crypto.Cipher import AES
"""
Decode FinSpy modules for Linux and MacOS

Author : Maciek mak@malwarelab.pl
Date: August 2020
"""


def unpack(data, s=0):
    """
    Decode the binary with aplib
    """
    cin = ctypes.c_buffer(data)
    cout = ctypes.c_buffer(s if s else len(data) * 20)
    aplib_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "_aplib.so")
    aPLIB = ctypes.cdll.LoadLibrary(aplib_path)
    n = aPLIB.aP_depack(cin, cout)
    return cout.raw[:n]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Unpack FinSpy modules')
    parser.add_argument('MODULE', help='Finspy module')
    args = parser.parse_args()

    with open(args.MODULE,'rb') as f:
        hmd5 = f.read(0x10)
        IV = f.read(0x10)
        data = f.read()

    hash_iv_data = hashlib.md5(IV + data)
    if hmd5 == hash_iv_data.digest():
        data = IV + data
        IV = b'\xd9!V\xee\xbe\x0c\xf9\x18*\xfaR;%&\xb7\x08'

    if hmd5 == hashlib.md5(data).digest():
        print('[+] DATA HASH match {}'.format(binascii.hexlify(hmd5)))

    key = b'YO\xf4\xa6\xd6\x1d\xd7!\xdc\x01A\xbfg\x83"m'
    xdata = AES.new(key,mode=AES.MODE_CBC,IV=bytes(IV)).decrypt(data)
    size = struct.unpack('I',xdata[:4])[0]
    print('[+] Unpacked size: {:x}'.format(size))
    depack = unpack(xdata[4:], size)
    with open(args.MODULE + '.unpacked.bin','wb') as f:
        f.write(depack)
    print('[*] saved to {}.unpacked.bin'.format(sys.argv[1]))
