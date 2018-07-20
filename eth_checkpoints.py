import logging
import json
import traceback
from insight_listener import InsightListener, get_block
from web3.auto import w3
from data_encoding import encode_block
from time import sleep
import consensus as cons


def submit_checkpoint(block, prev_block):
    data = encode_block(block, use_header=True, use_reduced_header=False)
    print(data)
    res = w3.eth.sendTransaction({
        'to': cons.cp_address,
        'data': '0x' + data
    })
    print(res)


class EthereumCheckpoints(InsightListener):

    def on_block(self, block_hash):
        block = get_block(block_hash)
        prev_block = get_block(block['previousblockhash'])
        print(json.dumps(block, indent=2))
        print(encode_block(block, prev_block))
        height = block['height']

        if cons.is_eligible_sub_height(height):
            print()
            print('Submitting checkpoint...')
            submit_checkpoint(block, prev_block)


    def on_disconnect(self):
        print('disconnected')
        self.stop()


if __name__ == '__main__':
    with EthereumCheckpoints() as c:
        while not c.stop_event.is_set():
            c.stop_event.wait(timeout=10)

