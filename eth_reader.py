from web3.auto import w3
import json
import codecs
from collections import defaultdict, namedtuple
from shutil import copyfile
from data_encoding import deserialize_header, is_verified_header, bfh, block_hash

"""Retrieves checkpoints from the Ethereum blockchain."""


class CpEntry(namedtuple('CpEntry', 'tx_index main_time sub_time main_sender')):
    pass

cp_address = '0x4d6f6e61636f696e20436865636B706f696e7473'
prefix = 'CpM1'
hex_prefix = '0x' + codecs.encode(prefix.encode('ascii'), 'hex').decode('ascii')
#print(hex_prefix)

data = {'height': 3671900, 'transactions': {}, 'blocks': {}}

try:
    with open('data.json', 'r') as f:
        data = json.load(f)

    copyfile('data.json', 'data.backup.json')

except FileNotFoundError:
    pass

def sync():
    global data
    new_height = w3.eth.blockNumber

    h0 = data['height'] - 10
    print('Blocks to sync: {}'.format(new_height - h0))
    if new_height > h0:

        for i in range(h0, new_height + 1):
            key = str(i)
            block = w3.eth.getBlock(i)
            data['blocks'][key] = {
                'timestamp': block.timestamp,
                'hash': block.hash.hex(),
                'parentHash': block.parentHash.hex()
            }

            data['transactions'][key] = []
            if i % 25 == 0:
                print('{:.4}% {}'.format(
                    100.0 * (i - h0) / (new_height - h0), i))

            blk = w3.eth.getBlock(i)
            for txid in blk.transactions:
                tx = w3.eth.getTransaction(txid)
                if tx.to == cp_address and tx.input.find(hex_prefix) == 0:
                    tx_data = {
                        'blockHash': tx.blockHash.hex(),
                        'transactionIndex': tx.transactionIndex,
                        'hash': tx.hash.hex(),
                        'blockNumber': tx.blockNumber,
                        'from': tx['from'],
                        'input': tx.input
                    }
                    #print(tx.input.strip('0x'))

                    data['transactions'][key].append(tx_data)

    data['height'] = new_height


sync()
#print(data)
#print(json.dumps(data, indent=2))
with open('data.json', 'w') as f:
    json.dump(data, f, indent=2, sort_keys=True)


cps_by_height = defaultdict(lambda: defaultdict(lambda: set()))
txs_by_height = data['transactions']

cp_period = 10


for hh, txs in txs_by_height.items():
    txs.sort(key=lambda tx: (tx.get('blockNumber'), tx.get('transactionIndex')))
    for tx in txs:
        tx_data = tx['input']
        data_stripped = tx_data[len(hex_prefix):]
        height = int('0x' + data_stripped[:6], 16)
        header = data_stripped[6:]
        decoded_header = deserialize_header(bfh(header), height=height)
        verified = is_verified_header(header, bits=decoded_header['bits'])
        order = (tx['blockNumber'], tx['transactionIndex'])
        bhash = block_hash(header)

        print('{}:{:3} | {:7} {}'.format(order[0], order[1], height, header))
        if not verified:
            print('  *** Proof of work is not verified.')
            continue

        print(json.dumps(decoded_header, indent=2))
        print(bhash)

        if height % cp_period == 0:
            entry = CpEntry(
                order,
                data['blocks'][str(tx['blockNumber'])]['timestamp'],
                decoded_header['time'],
                tx['from']
            )
            cps_by_height[height][bhash].add(entry)

import pprint
pprint.pprint({
    k: {k1: sorted(map(tuple, v1)) for k1, v1 in v.items()}
    for k, v in cps_by_height.items()
}, width=200)
