# This module incorporates code from Electrum and Electrum-Mona.
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import print_function
import sys
import codecs
import binascii
import requests
import hashlib

import lyra2re2_hash

def encode_height(h):
    h0 = hex(h)[2:]
    return ('0' * (6 - len(h0))) + h0


def encode_block(b, prev_block=None, use_header=True, use_reduced_header=True, height=None):
    prefix = 'CpM' + ('1' if use_header else '0')
    prefix_bytes = bytes(prefix, 'utf-8')
    prefix_hex = codecs.encode(prefix_bytes, 'hex').decode('utf-8')

    if use_header:
        body = (
            serialize_reduced_header(b, prev_time=prev_block.get('time'))
            if use_reduced_header
            else serialize_header(b)
        )
    else:
        body = b['hash']

    if height is None: height = b['height']
    return prefix_hex + encode_height(height) + body


def powhash(header):
    return rev_hex(bh2u(lyra2re2_hash.getPoWHash(bfh(header))))


def get_target(bits):
    return rev_hex(int_to_hex(convbignum(int('0x' + bits, 16)), 32))


def is_verified_header(header, bits=None):
    if bits is None:
        bits = deserialize_header(bfh(header), None)['bits']

    _powhash, _target = powhash(header), get_target(bits)
    assert len(_powhash) == len(_target)
    # string comparison works because both hex strings have same number of characters
    return _powhash <= _target
    #return int('0x' + powhash(header), 16) <= int('0x' + get_target(bits), 16)


def block_hash(header):
    dhash = hashlib.sha256(hashlib.sha256(bfh(header)).digest()).digest()
    return rev_hex(codecs.encode(dhash, 'hex').decode('ascii'))


# bitcoin.py and util.py

hash_encode = lambda x: bh2u(x[::-1])

bfh = bytes.fromhex
hfu = binascii.hexlify


def bh2u(x):
    return hfu(x).decode('ascii')


def rev_hex(s):
    return bh2u(bfh(s)[::-1])


def int_to_hex(i, length=1):
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('int_to_hex: {!r} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -range_size/2 or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)


# blockchain.py
def serialize_reduced_header(res, prev_time):
    s = rev_hex(res.get('merkleroot')) \
        + int_to_hex(int(res.get('time') - prev_time), 2) \
        + int_to_hex(int(res.get('bits'), 16), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s


def deserialize_reduced_header(
    s, height=None, prev_time=None, version=None, previousblockhash=None):
    if not s:
        raise Exception('Invalid header: {}'.format(s))
    if len(s) != 42:
        raise Exception('Invalid header length: {}'.format(len(s)))
    h = {}
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h['version'] = version
    h['previousblockhash'] = previousblockhash
    h['merkleroot'] = hash_encode(s[0:32])
    h['time'] = prev_time + hex_to_int(s[32:34])
    h['bits'] = rev_hex(int_to_hex(hex_to_int(s[34:38]), 4))
    h['nonce'] = hex_to_int(s[38:42])
    h['height'] = height
    return h


def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('previousblockhash')) \
        + rev_hex(res.get('merkleroot')) \
        + int_to_hex(int(res.get('time')), 4) \
        + int_to_hex(int(res.get('bits'), 16), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s


def deserialize_header(s, height=None):
    if not s:
        raise Exception('Invalid header: {}'.format(s))
    if len(s) != 80:
        raise Exception('Invalid header length: {}'.format(len(s)))
    h = {}
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h['version'] = hex_to_int(s[0:4])
    h['previousblockhash'] = hash_encode(s[4:36])
    h['merkleroot'] = hash_encode(s[36:68])
    h['time'] = hex_to_int(s[68:72])
    h['bits'] = rev_hex(int_to_hex(hex_to_int(s[72:76]), 4))
    h['nonce'] = hex_to_int(s[76:80])
    h['height'] = height
    return h


# not used
def convbits(new_target):
    c = ("%064x" % int(new_target))[2:]
    while c[:2] == '00' and len(c) > 6:
        c = c[2:]
    bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
    if bitsBase >= 0x800000:
        bitsN += 1
        bitsBase >>= 8
    new_bits = bitsN << 24 | bitsBase
    return new_bits


def convbignum(bits):
    MM = 256*256*256
    a = bits%MM
    if a < 0x8000:
        a *= 256
    target = (a) * pow(2, 8 * (bits//MM - 3))
    return target

