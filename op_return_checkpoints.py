from insight_listener import *
from op_return import OP_RETURN_store, OP_RETURN_hex_to_bin
import consensus as cons

def submit_checkpoint(block, prev_block):
    data = encode_block(block, prev_block, True, True)
    print(data)
    res = OP_RETURN_store(OP_RETURN_hex_to_bin(data))
    print(res)


class BitcoinRPCCheckpoints(InsightListener):

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
    with BitcoinRPCCheckpoints() as c:
        while not c.stop_event.is_set():
            c.stop_event.wait(timeout=10)

