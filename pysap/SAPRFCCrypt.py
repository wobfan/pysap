import random
import time
import socket
import struct

key = '\xf0\xed\x53\xb8\x32\x44\xf1\xf8\x76\xc6\x79\x59\xfd\x4f\x13\xa2\xc1\x51\x95' \
      '\xec\x54\x83\xc2\x34\x77\x49\x43\xa2\x7d\xe2\x65\x96\x5e\x53\x98\x78\x9a\x17' \
      '\xa3\x3c\xd3\x83\xa8\xb8\x29\xfb\xdc\xa5\x55\xd7\x02\x77\x84\x13\xac\xdd\xf9' \
      '\xb8\x31\x16\x61\x0e\x6d\xfa'


def char(integer, n=0):
    byte = hex((integer & 0xFF << (8 * n)) >> (8 * n))
    byte = byte[2:]
    byte_int = 0
    exec ("byte_int = 0x%s" % byte)
    return byte_int


def int2char(integer):
    string = ""
    for i in range(0, 4):
        string += chr(char(integer, n=i))
    return string


def encrypt(password):
    random.seed(time.time())
    rand = random.randint(0, 32767)

    rand = rand ^ (rand * pow(2, 14))
    rand = socket.htonl(rand)
    passwd = ""

    next_offset = rand >> 5 ^ 2 * rand ^ rand

    for i in range(0, len(password)):
        offset = next_offset % 64
        next_offset = offset + 1
        encr = ord(password[i]) ^ (char(i) * char(rand) - 1) * char(i) ^ ord(key[offset])
        passwd += chr(encr % 256)
    passwd = int2char(rand) + passwd
    return passwd


def decrypt(password):
    random = password[:4]
    password = password[4:]
    decrypted = ""

    random, = struct.unpack('<i', random)

    for i in range(0, len(password)):
        next_offset = random >> 5 ^ random * 2 ^ random
        offset = 0
        for j in range(0, i + 1):
            offset = next_offset % 64
            next_offset = offset + 1
        decr = ord(password[i]) ^ (char(i) * char(random) - 1) * char(i) ^ ord(key[offset])
        decrypted += chr(decr % 256)
    return decrypted
