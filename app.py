from flask import Flask, request, jsonify
import asyncio
from concurrent.futures import ProcessPoolExecutor
import logging
import secrets
from eth_account import Account
from eth_utils import keccak, to_normalized_address


app = Flask(__name__)
executor = ProcessPoolExecutor()

logging.basicConfig(level=logging.INFO)  # Set the logging level to DEBUG
MAX_ITERATIONS = 100000000  # Adjust this value as needed

class Topology:
    def __init__(self, depth):
        self.depth = depth

    def num_neighbourhoods(self):
        return 1 if self.depth == 0 else 2 ** self.depth

    def neighbourhood_bitmask(self):
        bit_mask = [0] * 32

        for i in range(self.depth):
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            bit_mask[byte_index] |= 1 << bit_index

        return bytes(bit_mask)

    def neighbourhood_size(self):
        if self.depth == 0:
            return 1
        return (2 ** 32) // (2 ** self.depth)

    def get_base_overlay_address(self, neighbourhood):
        address = bytearray(32)
        offset = int(neighbourhood) * self.neighbourhood_size()
    
        for i in range(4):
            address[i] = (offset >> ((3 - i) * 8)) & 0xFF
    
        return bytes(address)


class MinedAddress:
    def __init__(self, radius, neighbourhood, topology):
        self.radius = radius
        self.neighbourhood = neighbourhood
        self.topology = topology
        self.base_overlay_address = self.topology.get_base_overlay_address(self.neighbourhood)[:3]
        self.bit_mask = self.topology.neighbourhood_bitmask()[:3]
        self.first_byte_base = self.base_overlay_address[0]
        self.logger = logging.getLogger('MinedAddress')

    def compare_overlay_address_with_base(self, overlay_address, base_overlay_address, bit_mask):
        if overlay_address[0] != self.first_byte_base:
            return False
        
        for i in range(1, 3):
            if overlay_address[i] & bit_mask[i] != base_overlay_address[i] & bit_mask[i]:
                return False
        
        return True

    def calculate_overlay_address(self, ethereum_address):
        ethereum_address_bytes = bytes.fromhex(ethereum_address[2:])
        overlay_hash = keccak(ethereum_address_bytes)
        return overlay_hash

    def generate_nonce(self):
        return secrets.token_bytes(32)

    def mine_wallet(self):
        match_found = False
        count = 0
    
        overlay_range_start = hex(int(self.neighbourhood) * (2 ** (16 - int(self.topology.depth))))[2:].zfill(4)
        overlay_range_end = hex((int(self.neighbourhood) + 1) * (2 ** (16 - int(self.topology.depth))) - 1)[2:].zfill(4)
    
        overlay_group = f"Group {int(overlay_range_start, 16):X} (0x{overlay_range_start} to 0x{overlay_range_end})"
        logging.info("Searching in overlay group: %s", overlay_group)
    
        while not match_found and count < MAX_ITERATIONS:
            private_key, eth_address = self.generate_ethereum_address()
            overlay_hash = self.calculate_overlay_address(eth_address)
    
            overlay_address_hex = overlay_hash.hex()[:6]  # Convert overlay hash to hex
            #overlay_address_hex = overlay_address_hex.lstrip("0x")  # Remove "0x" prefix if exists
            #overlay_range_start = overlay_range_start.lstrip("0x")
            #overlay_range_end = overlay_range_end.lstrip("0x")
    
            logging.debug(
                "Private Key: %s, Ethereum Address: %s, Overlay: %s, Searching in: Overlay Range %06x-%06x (Depth %s)",
                private_key,
                eth_address,
                overlay_address_hex,
                overlay_range_start,
                overlay_range_end,
                self.topology.depth
            )
    
            if overlay_range_start <= overlay_address_hex <= overlay_range_end:
                match_found = True
                logging.debug("Match found after %d iterations...", count)
    
            count += 1
    
        if match_found:
            return {
                'private_key': private_key,
                'ethereum_address': eth_address,
                'overlay_address': overlay_hash.hex(),
            }
        return None 

    def generate_ethereum_address(self):
        private_key_bytes = secrets.token_bytes(32)
        private_key_hex = private_key_bytes.hex()
        private_key = "0x" + private_key_hex

        acct = Account.from_key(private_key)
        eth_address = acct.address
        return private_key, eth_address


# Integrate the MinedAddress class into the generate_wallet_async function
async def generate_wallet_async(depth, neighbourhood, radius, num_processes=1):
    topology = Topology(depth)
    tasks = []

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        for _ in range(num_processes):
            mined_address = MinedAddress(radius, neighbourhood, topology)
            task = asyncio.get_event_loop().run_in_executor(executor, mined_address.mine_wallet)
            tasks.append(task)

        mined_wallets = await asyncio.gather(*tasks)
        valid_wallets = [wallet for wallet in mined_wallets if wallet is not None]
        return valid_wallets

@app.route('/generate_wallet', methods=['GET'])
def generate_wallet():
    neighbourhood = request.args.get('n')
    depth = request.args.get('d')

    if neighbourhood is None or depth is None:
        return jsonify({'error': 'Neighbourhood and depth parameters are required.'}), 400

    radius = 3
    num_processes = 16

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(generate_wallet_async(int(depth), neighbourhood, radius, num_processes))

    if result:
        return jsonify(result[0]), 200
    else:
        return jsonify({'error': 'No valid wallet found.'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

