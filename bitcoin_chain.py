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


if __name__ == '__main__':
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

