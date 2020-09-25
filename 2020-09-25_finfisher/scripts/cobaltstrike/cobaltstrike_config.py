import argparse
import struct
import re
import sys
import json

"""
Extract configuration from a Cobalt Strike decrypted beacon

Author : Etienne Maynier, Amnesty Tech
Date : March 2020
"""

CONFIG_STRUCT = {
    1: "dns_ssl",
    2: "port",
    3: ".sleeptime",
    4: ".http-get.server.output",
    5: ".jitter",
    6: ".maxdns",
    7: "publickey",
    8: ".http-get.uri",
    9: ".user-agent",
    10: ".http-post.uri",
    11: ".http-get.server.output",
    12: ".http-get.client",
    13: ".http-post.client",
    14: ".spawnto",
    15: "unknown",
    19: ".dns_idle",
    20: ".dns_sleep ",
    26: ".http-get.verb",
    27: ".http-post.verb",
    28: "shouldChunkPosts",
    29: ".post-ex.spawnto_x86",
    30: ".post-ex.spawnto_x64",
    31: "cryptoscheme",
    37: "watermark",
    38: ".stage.cleanup",
    39: "CFGCaution",
    50: "cookieBeacon"
}
CONFIG_SIZE = 1978

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
             return obj.hex()
        return json.JSONEncoder.default(self, obj)


def search_config(data):
    r = re.search(b"ihihik.{2}ikihik", data)
    if r:
        return r.span()[0]
    else:
        return None


def decode_config(data):
    config = {}
    i = 0
    while i < len(data) - 8:
        dec = struct.unpack(">HHH", data[i:i+6])
        if dec[0] == 1:
            v = struct.unpack(">H", data[i+6:i+8])[0]
            config["dns"] = ((v & 1) == 1)
            config["ssl"] = ((v & 8) == 8)
        elif dec[0] in CONFIG_STRUCT.keys():
            if dec[1] == 1 and dec[2] == 2:
                # Short
                config[CONFIG_STRUCT[dec[0]]] = struct.unpack(">H", data[i+6:i+8])[0]
            elif dec[1] == 2 and dec[2] == 4:
                # Int
                config[CONFIG_STRUCT[dec[0]]] = struct.unpack(">I", data[i+6:i+10])[0]
            elif dec[1] == 3:
                # Byte or string
                v = data[i+6:i+6+dec[2]]
                try:
                    config[CONFIG_STRUCT[dec[0]]] = v.decode('utf-8').strip('\x00')
                except UnicodeDecodeError:
                    config[CONFIG_STRUCT[dec[0]]] = v
        else:
            print("Unknown config command {}".format(dec[0]))
        # Add size +
        i += dec[2] + 6
    return config


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract Cobalt Strike configuration')
    parser.add_argument('PAYLOAD', help='A Cobalt Strike beacon')
    parser.add_argument('--json', '-j', action="store_true", help='Print json')
    args = parser.parse_args()

    with open(args.PAYLOAD, "rb") as f:
        data = f.read()

    START = search_config(data)
    if not START:
        print("Start position of the config struct not found")
        sys.exit(-1)

    # Configuration is xored with 105
    conf = bytearray([c ^ 105 for c in data[START:START+CONFIG_SIZE]])

    config = decode_config(conf)
    if args.json:
        print(json.dumps(config, indent=4, sort_keys=True, cls=JsonEncoder))
    else:
        for d in config:
            if isinstance(config[d], bytearray):
                print("{} : {}".format(d, config[d].hex()))
            else:
                print("{} : {}".format(d, config[d]))
