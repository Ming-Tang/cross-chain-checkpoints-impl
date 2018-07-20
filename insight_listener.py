from __future__ import print_function, division
import logging
import json
import sys
from time import sleep
import traceback
import threading

from contextlib import contextmanager


logging.getLogger('socketIO-client').setLevel(logging.INFO)
logging.basicConfig()

from socketIO_client import SocketIO, LoggingNamespace
import requests

from data_encoding import (
    encode_block,
    serialize_header, deserialize_header, deserialize_reduced_header,
    serialize_reduced_header, bfh,
    powhash, get_target, is_verified_header
)

endpoint = 'https://mona.insight.monaco-ex.org/insight-api-monacoin'
insight_ws_endpoint = 'mona.insight.monaco-ex.org/socket.io'


def get_hash(height):
    return requests.get('{}/block-index/{}'.format(endpoint, height)).json()['blockHash']


def get_block(block_hash):
    return requests.get('{}/block/{}'.format(endpoint, block_hash)).json()



def test_validation():

    header_keys = (
        'version', 'previousblockhash', 'merkleroot',
        'time', 'bits', 'nonce', 'height'
    )

    blocks = requests.get('{}/blocks?limit=100'.format(endpoint)).json()['blocks']
    for b in blocks:
        block_hash = b['hash']
        print('')
        print(block_hash)
        block = get_block(block_hash)
        height = block['height']
        if not block:
            continue

        prev_block = get_block(block['previousblockhash'])
        prev_time = prev_block['time']
        header = serialize_header(block)
        reduced_header = serialize_reduced_header(block, prev_time)

        print(header, 'header', len(header) // 2)

        orig = {k: block.get(k) for k in header_keys}
        ds_header = deserialize_header(bfh(header), height=height)
        print('ds_header', json.dumps(ds_header, indent=2))
        print('orig', json.dumps(orig, indent=2))

        args = dict(
            version=prev_block.get('version'),
            prev_time=prev_block.get('time'),
            previousblockhash=prev_block.get('hash'))
        ds_reduced_header = deserialize_reduced_header(bfh(reduced_header), height=height, **args)
        print('ds_reduced_header', json.dumps(ds_reduced_header, indent=2))
        print('orig', json.dumps(orig, indent=2))

        assert repr(orig) == repr(ds_header)
        assert repr(orig) == repr(ds_reduced_header)

        print(reduced_header, 'reduced_header', len(reduced_header) // 2)

        print(get_target(block['bits']), 'target')
        print(powhash(header), 'powhash')
        print(is_verified_header(header))


class ThreadStopped(Exception): pass

# https://stackoverflow.com/a/47917281/303939
class InsightListener(threading.Thread):

    def __init__(self, seconds=10, ws_endpoint=None):
        threading.Thread.__init__(self, name='InsightListener')
        self.stop_event = threading.Event()
        self.seconds = seconds
        self.ws_endpoint = ws_endpoint or insight_ws_endpoint

    def run(self):
        with SocketIO(self.ws_endpoint, 80) as sock:
            self.sock = sock
            print('Connected to blocks websocket.')
            sock.emit('subscribe', 'inv')
            sock.on('block', self.on_block)
            sock.on('disconnect', self.on_disconnect)
            while not self.stop_event.is_set():
                sock.wait(seconds=self.seconds)

        self.stop()

    def stop(self):
        self.stop_event.set()

    def on_block(self, *args, **kwargs):
        print('on_block', args, kwargs)

    def on_disconnect(self, *args, **kwargs):
        print('on_disconnect', args, kwargs)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()
        print('Force set Thread Sleeper stop_event')


