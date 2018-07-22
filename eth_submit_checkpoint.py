import sys
from web3.auto import w3
from insight_listener import get_hash, get_block
from data_encoding import encode_block
import consensus as cons


"""Submit checkpoint given block hash (or height) and optional block height override."""


def encode_from_hash(block_hash, height=None):
    block = get_block(block_hash)
    return encode_block(block, use_header=True, use_reduced_header=False, height=height)


if len(sys.argv) < 2:
    print('Not enough arguments.')
    raise SystemExit(1)


try:
    block_hash = get_hash(int(sys.argv[1]))
except ValueError:
    block_hash = sys.argv[1]


data = encode_from_hash(block_hash, None if len(sys.argv) < 3 else int(sys.argv[2]))
res = w3.eth.sendTransaction({
    'to': cons.cp_address,
    'data': '0x' + data
})
print(res)

