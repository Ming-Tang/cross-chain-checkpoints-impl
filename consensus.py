
"""Consensus parameters for cross-chain checkpoints."""

# All time measurements are in seconds

# Main chain Ethereum address that houses the checkpoints
cp_address = '0x4d6f6e61636f696e20436865636B706f696e7473'

main_height_init = 3671900

sub_block_time = 90

# Determines sub block heights that are checkpoint-eligible
sub_block_period = 10
sub_block_phase = 0

def is_eligible_sub_height(height):
    return height % sub_block_period == sub_block_phase

addrtype = 50 # 'M'
msg_prefix = b"\x19Monacoin Signed Message:\n"

