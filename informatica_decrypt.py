#!/usr/bin/env python3
import argparse
import base64
import re
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

parser = argparse.ArgumentParser(description = 'Decrypt Informatica passwords')
parser.add_argument('-k', '--sitekey', type=str, required=True)
parser.add_argument('secret', type=str)
args = parser.parse_args()

secret_data = base64.b64decode(args.secret)

with open(args.sitekey, 'rb') as f:
    sitekey_data = f.read()

if sitekey_data[3] == 16:           # 10.4
    key = sitekey_data[4:20]
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex('19a61c4ffc9bd0efa86a2dde32cd6cb0'))
    pt = unpad(cipher.decrypt(secret_data), 16)
elif sitekey_data[3] == 32:         # 10.5
    key = sitekey_data[4:36]

    # find envelope pattern: 00 00 00 01 00 00 00 xx 00 00 00 00
    envelopes = re.finditer(b'\x00\x00\x00\x01\x00\x00\x00.\x00\x00\x00\x00', secret_data)
    for envelope in envelopes:
        iv = secret_data[envelope.end() + 4:envelope.end() + 20]
        secret_len = secret_data[envelope.end() + 20:envelope.end() + 24]
        secret = secret_data[envelope.end() + 24:envelope.end() + 24 + int.from_bytes(secret_len)]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(secret), 16)
        key = pt
else:
    print("Unrecognized key")
    exit(1)

print(pt)
