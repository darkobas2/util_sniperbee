from flask import Flask, request, jsonify
import asyncio
from concurrent.futures import ProcessPoolExecutor
import logging
import secrets
from eth_account import Account
from eth_utils import keccak, to_normalized_address


app = Flask(__name__)
executor = ProcessPoolExecutor()

logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG
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
        self.base_overlay_address = self.topology.get_base_overlay_address(self.neighbourhood)[:3]  # Keep the first three bytes
        self.bit_mask = self.topology.neighbourhood_bitmask()[:3]  # Keep the first three bytes
        self.first_byte_base = self.base_overlay_address[0]  # Store the first byte
        self.logger = logging.getLogger('MinedAddress')

    def compare_overlay_address_with_base(self, overlay_address, base_overlay_address, bit_mask):
        if overlay_address[0] != self.first_byte_base:
            return False
        
        for i in range(1, 3):
            if overlay_address[i] & bit_mask[i] != base_overlay_address[i] & bit_mask[i]:
                return False
        
        return True
    def mine_wallet(self):
        match_found = False
        count = 0

        while not match_found and count < MAX_ITERATIONS:
            private_key, eth_address = self.generate_ethereum_address()
            overlay_address = self.calculate_overlay_address(private_key)
            logging.debug("Private Key: %s, Ethereum Address: %s, Overlay: %s", private_key, eth_address, overlay_address) 

            character_match = False

            if overlay_address[0] != self.first_byte_base:
                count += 1
                continue

            for i in range(1, 3):
                if overlay_address[i] & self.bit_mask[i] == self.base_overlay_address[i] & self.bit_mask[i]:
                    self.logger.debug("Character match found for byte %d", i)
                    character_match = True
                    break

            if character_match:
                if self.compare_overlay_address_with_base(overlay_address, self.base_overlay_address, self.bit_mask):
                    private_key, eth_address = self.generate_ethereum_address()
                    match_found = True

            count += 1
            logging.debug("count increase to %d", count)
    
        if match_found:
            return {
                'private_key': private_key,
                'ethereum_address': eth_address
            }
        return None

    def generate_ethereum_address(self):
        private_key_bytes = secrets.token_bytes(32)
        private_key_hex = private_key_bytes.hex()
        private_key = "0x" + private_key_hex

        acct = Account.from_key(private_key)
        eth_address = acct.address
        return private_key, eth_address

    def calculate_overlay_address(self, private_key):
        acct = Account.from_key(private_key)
        public_key = acct._key_obj.public_key
        public_key_bytes = public_key.to_bytes()
        overlay_hash = keccak(public_key_bytes).hex()[:12]
        return overlay_hash


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

# Update the generate_wallet route to exclude network_id parameter
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

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

