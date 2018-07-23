from web3.auto import w3
import json
import codecs
from collections import defaultdict, namedtuple
from shutil import copyfile
from data_encoding import deserialize_header, is_verified_header, bfh, block_hash
import consensus as cons

"""Retrieves checkpoints from the Ethereum blockchain."""


class CpEntry(namedtuple('CpEntry', 'tx_index main_time sub_time main_sender')):
    pass

prefix = 'CpM1'
hex_prefix = '0x' + codecs.encode(prefix.encode('ascii'), 'hex').decode('ascii')
#print(hex_prefix)


data = None


def find_initial_height(h0):
    global data
    while True:
        last_hash = data['blocks'][str(h0)]['hash']
        next_block = w3.eth.getBlock(h0 + 1)
        if not next_block:
            break
        parent_hash = next_block.parentHash.hex()
        if parent_hash != last_hash:
            h0 -= 1
        else:
            break

    return h0


def import_block(i, last_hash):
    global data
    key = str(i)
    block = w3.eth.getBlock(i)
    print(block.hash.hex(), block.parentHash.hex() == last_hash)
    last_hash = block.hash.hex()

    data['blocks'][key] = {
        'timestamp': block.timestamp,
        'hash': block.hash.hex(),
        'parentHash': block.parentHash.hex()
    }

    data['transactions'][key] = []

    for txid in block.transactions:
        tx = w3.eth.getTransaction(txid)
        if tx.to == cons.cp_address and tx.input.find(hex_prefix) == 0:
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

    return last_hash


def sync():
    global data
    new_height = w3.eth.blockNumber
    h0 = find_initial_height(data['height'])
    print('Blocks to sync: {}'.format(new_height - h0))

    if new_height > h0:
        last_hash = data['blocks'][str(h0 - 1)]['hash']

        for i in range(h0, new_height + 1):
            if i % 25 == 0:
                print('{:.4}% {}'.format(
                    100.0 * (i - h0) / (new_height - h0), i))

            last_hash = import_block(i, last_hash)


    data['height'] = new_height


def import_tx(tx):
    global data
    tx_data = tx['input']
    data_stripped = tx_data[len(hex_prefix):]
    height = int('0x' + data_stripped[:6], 16)
    header = data_stripped[6:]
    decoded_header = deserialize_header(bfh(header), height=height)
    verified = is_verified_header(header, bits=decoded_header['bits'])
    order = (tx['blockNumber'], tx['transactionIndex'])
    bhash = block_hash(header)

    #print('{}:{:3} | {:7} {}'.format(order[0], order[1], height, header))
    if not verified:
        print('  *** Proof of work is not verified.')
        return False

    if existing_headers.get(header, None) not in (None, height):
        print('  *** Header already exists in another height: ', existing_headers.get(header))
        return False

    existing_headers[header] = height

    if cons.is_eligible_sub_height(height):
        entry = CpEntry(
            order,
            data['blocks'][str(tx['blockNumber'])]['timestamp'],
            decoded_header['time'],
            tx['from']
        )
        cps_by_height[height][bhash].add(entry)

        return True

    return False


def load_data():
    global data
    data = {'height': cons.main_height_init, 'transactions': {}, 'blocks': {}}

    try:
        with open('data.json', 'r') as f:
            data = json.load(f)

        copyfile('data.json', 'data.backup.json')

    except FileNotFoundError:
        pass


def save_data():
    global data
    with open('data.json', 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)


if __name__ == '__main__':

    load_data()
    sync()
    save_data()


    existing_headers = {}
    cps_by_height = defaultdict(lambda: defaultdict(lambda: set()))
    txs_by_height = data['transactions']

    print('')

    for hh, txs in txs_by_height.items():
        txs.sort(key=lambda tx: (tx.get('blockNumber'), tx.get('transactionIndex')))
        for tx in txs:
            import_tx(tx)

    print('')
    import pprint
    pprint.pprint({
        k: {k1: sorted((tuple(t), t.main_time - t.sub_time) for t in v1) for k1, v1 in v.items()}
        for k, v in sorted(cps_by_height.items(), reverse=True)
    }, width=200)

