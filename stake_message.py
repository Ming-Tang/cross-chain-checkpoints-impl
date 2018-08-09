from __future__ import print_function
import sys
import codecs
import traceback
import json
import requests
import click
import gzip
import base64

from decimal import Decimal, getcontext

"""Tool to sign staking messages."""

getcontext().prec = 8

default_prefix = 'M0.'
default_max_txos = 40
max_value = Decimal(10000)
base_height = 1000

insight_endpoint = 'https://mona.insight.monaco-ex.org/insight-api-monacoin'


def get(url):
    return requests.get('{}{}'.format(insight_endpoint, url)).json()


def get_tx_index(hash, txid):
    block = get('/block/{}'.format(hash))
    try:
        return block.get('tx', []).index(txid)
    except ValueError:
        return None


def get_items(addr):
    resp = get('/addr/{}'.format(addr))
    txs = resp.get('transactions', [])

    results = []
    for txid in txs:
        tx = get('/tx/{}'.format(txid))
        height = tx.get('blockheight')
        block_hash = tx.get('blockhash')
        for o in tx.get('vout', []):
            spent = o.get('spentHeight')
            if spent is not None and spent <= base_height:
                continue

            if o.get('scriptPubKey', {}).get('addresses') == [addr]:
                yield (
                    (block_hash, txid),
                    (height, get_tx_index(block_hash, txid), o.get('n')),
                    Decimal(o.get('value'))
                )


@click.group()
def cli():
    pass


@cli.command()
@click.option('--max-txos', default=default_max_txos, help='maximum number of transaction outputs to include')
@click.argument('addr')
def encode(max_txos, addr):
    total = Decimal()
    msg_parts = []
    for i, item in enumerate(get_items(addr)):
        if i > max_txos: break
        h, idx, val = item
        total += val
        print(i, (idx, val, total), file=sys.stderr)
        msg_parts.append(idx)

    msg = '.'.join('{}:{}'.format(h, i, j) for h, i, j in msg_parts)
    print('', file=sys.stderr)
    print('Please sign the following message using your provided address:', file=sys.stderr)
    print(msg)


if sys.version_info >= (3, 0):
    raw_input = input
    B = lambda x: bytes(x, 'ascii')
else:
    B = bytes

@cli.command()
@click.option('--prefix', default=default_prefix, help='prefix for the messages')
@click.argument('addr', default=None)
def assemble(prefix, addr):
    message = raw_input('Enter the message: ')
    signature = raw_input('Enter the signature: ')

    if addr:
        from bitcoin_sigmessage import verify_message
        success = False
        try:
            success = verify_message(addr, signature, message)
        except:
            traceback.print_exc(file=sys.stderr)
        finally:
            if not success:
                print('Signature verification failed.', file=sys.stderr)
                raise SystemExit(1)


    encoded = B(prefix) + gzip.compress(B(message)) + base64.b64decode(signature)
    print('', file=sys.stderr)
    print('In your checkpoint submission address, enter the following line as data:', file=sys.stderr)
    print((b'0x' + codecs.encode(encoded, 'hex')).decode('ascii'))


if __name__ == '__main__':
    cli()
