from bitcoin_rpc import bitcoin_rpc
import json

def get_tips():
    return bitcoin_rpc('getchaintips')


def get_block_hash(height):
    return bitcoin_rpc('getblockhash', [height])


def get_block(arg):
    if isinstance(arg, int):
        hash = get_block_hash(arg)
    else:
        hash = arg

    return bitcoin_rpc('getblock', [hash])


def get_parent_at(height, hash):
    block = get_block(hash)
    assert block['height'] >= height
    while block['height'] > height:
        block = get_block(block['previousblockhash'])

    return block


def get_block_hash_tip(height, tip_hash):
    tip_block = get_block(tip_hash)
    tip_height = tip_block['height']
    tip_hash = tip_block['previousblockhash']

    if height > tip_height:
        return None
    elif height == tip_height:
        return tip_block
    else:
        return get_parent_at(height, tip_hash)


def get_tx(txid):
    raw_tx = bitcoin_rpc('getrawtransaction', [txid, False])
    return bitcoin_rpc('decoderawtransaction', [raw_tx])


def get_utxo(parts):
    block, tx_index, vout_idx = parts
    blk = get_block(block)
    if not blk: return None

    txid = blk.get('tx', [])[tx_index]
    tx = get_tx(txid)
    if not tx: return None

    return tx.get('vout', [])[vout_idx]


if __name__ == '__main__':
    #print(bitcoin_rpc('getblockchaininfo'))
    #print()
    #print(get_tx('4f3844ab4faa93df30d0f4d1f83fbfbdf57c96052a7ec22b136af5d6e7622a02'))
    print(get_utxo([1402455, 1, 1]))
    print(get_tx('b821de8a533adf600acd1b6625a221921e8f651c0cd19b77b3f0d84f76f4a78a'))

    for tip in get_tips():
        tip_height, tip_hash = tip['height'], tip['hash']
        print()
        print(tip)
        for i in range(3):
            height = tip_height - i
            print(height,
                get_parent_at(height, tip_hash)['hash'],
                get_block(height)['hash'])


    #print(json.dumps(get_tips(), indent=2))
    #print(json.dumps(get_block(1390613), indent=2))

