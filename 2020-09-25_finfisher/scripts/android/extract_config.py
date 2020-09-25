import argparse
import sys
import struct
import re
import os
import base64
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf
"""
Decode configuration from Android
Python3 only
"""

__author__      = "Etienne Maynier"

def extract_apk_config(data):
    """
    Extract configuration from apks
    Based on
    https://github.com/SpiderLabs/malware-analysis/tree/master/Ruby/FinSpy
    https://github.com/devio/FinSpy-Tools/blob/master/Android/finspyCfgExtract.py
    """
    b64 = ''
    for zf in re.finditer(b'PK\x01\x02', data):
        pos = zf.span()[0]
        try:
            id, \
            version, host_os, min_version, target_os, \
            gp_flags, compression_method, \
            file_time, file_crc, file_size_compressed, file_size_uncompressed, \
            filename_len, extrafield_len, comment_len, disk_number, \
            hidden_data, \
            local_hdr_offset = struct.unpack("<I4c2H4I4H6sI", data[pos:pos+46])
            internal_bm, external_bm = struct.unpack("<HI", hidden_data)
        except Exception as e:
            print("[e] Error unpacking data from CDS: {}".format(e))
        else:
            #return None
            if (internal_bm & 0xfffa) > 0:
                try:
                    hd = hidden_data.decode('utf-8').strip("\x00")
                    if hd.isprintable():
                        b64 += hd
                except UnicodeDecodeError:
                    print("Error with {}".format(hidden_data))

    if b64 == '':
        return None
    else:
        try:
            return base64.b64decode(b64)
        except Exception:
            print("Impossible to decode the Base 64 data")
            return None


def extract_config(fpath):
    config_re = re.compile(b'.{4}\x90\[\xfe\x00.{4}\xa0\x33\x84\x00')
    if androconf.is_android(fpath) == "APK":
        print("APK file")
        with open(fpath, 'rb') as f:
            data = f.read()
        # Get dex file
        a = APK(fpath)
        dex = a.get_dex()
        search_conf = config_re.search(dex)
        if search_conf is not None:
            print("Configuration struct found in the DEX file")
            size = struct.unpack('I', dex[search_conf.span()[0]:search_conf.span()[0]+4])[0]
            config_data = dex[search_conf.span()[0]:search_conf.span()[0]+size]
        else:
            # Searching in APK
            config_data = extract_apk_config(data)
            if config_data is None:
                print("Config data not found")
            else:
                print("Config data found in the apk")
            return config_data
    elif androconf.is_android(fpath) == "DEX":
        print("DEX file")
        with open(fpath, 'rb') as f:
            data = f.read()
        search_conf = config_re.search(data)
        if search_conf is not None:
            print("Configuration struct found in the dex")
            size = struct.unpack('I', data[search_conf.span()[0]:search_conf.span()[0]+4])
            config_data = data[search_conf.span()[0]:search_conf.span()[0]+size]
            return config_data
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract FinSpy conf from Android samples')
    parser.add_argument('FILE', help='Android sample')
    args = parser.parse_args()

    config = extract_config(args.FILE)
    dpath = os.path.splitext(args.FILE)[0] + ".config"

    if os.path.isfile(dpath):
        print("Target file already exist")
        sys.exit(1)

    if config:
        with open(dpath, 'wb+') as f:
            f.write(config)
        print("Written in {}".format(dpath))
    else:
        print("config not found")
