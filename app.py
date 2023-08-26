from flask import Flask, request, jsonify
import asyncio
from concurrent.futures import ProcessPoolExecutor
import logging, os, secrets, json, requests, random
from eth_account import Account
from eth_utils import keccak, to_normalized_address
from web3.auto import w3
from eth_account.datastructures import SignedTransaction


app = Flask(__name__)
executor = ProcessPoolExecutor()

logging.basicConfig(level=logging.INFO)  # Set the logging level to DEBUG
MAX_ITERATIONS = 100000000  # Adjust this value as needed

class MinedAddress:
    def __init__(self, radius, neighbourhood, depth):
        self.radius = radius
        self.neighbourhood = neighbourhood
        self.depth = depth
        self.logger = logging.getLogger('MinedAddress')

    def calculate_overlay_address(self, ethereum_address):
        ethereum_address_bytes = bytes.fromhex(ethereum_address[2:])
        overlay_hash = keccak(ethereum_address_bytes)
        return overlay_hash

    def mine_wallet(self):
        match_found = False
        count = 0
    
        overlay_range_start = hex(int(self.neighbourhood) * (2 ** (16 - int(self.depth))))[2:].zfill(4)
        overlay_range_end = hex((int(self.neighbourhood) + 1) * (2 ** (16 - int(self.depth))) - 1)[2:].zfill(4)
    
        overlay_group = f"Group {int(overlay_range_start, 16):X} (0x{overlay_range_start} to 0x{overlay_range_end})"
        logging.info("Searching in overlay group: %s", overlay_group)
    
        while not match_found and count < MAX_ITERATIONS:
            private_key, eth_address = self.generate_ethereum_address()
            overlay_hash = self.calculate_overlay_address(eth_address)
    
            overlay_address_hex = overlay_hash.hex()[:6]  # Convert overlay hash to hex
    
            logging.debug(
                "Private Key: %s, Ethereum Address: %s, Overlay: %s, Searching in: Overlay Range %06x-%06x (Depth %s)",
                private_key,
                eth_address,
                overlay_address_hex,
                overlay_range_start,
                overlay_range_end,
                self.depth
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


def encrypt_private_key(private_key, password):
    keystore = w3.eth.account.encrypt(private_key, password)
    return keystore

async def generate_wallet_async(depth, neighbourhood, radius, num_processes=1):
    tasks = []

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        for _ in range(num_processes):
            mined_address = MinedAddress(radius, neighbourhood, depth)
            task = asyncio.get_event_loop().run_in_executor(executor, mined_address.mine_wallet)
            tasks.append(task)

        mined_wallets = await asyncio.gather(*tasks)
        valid_wallets = [wallet for wallet in mined_wallets if wallet is not None]
        return valid_wallets

def find_lowest_neighbourhood():
    response = requests.get("https://api.swarmscan.io/v1/network/neighborhoods")
    data = response.json()
    
    chosen_depth = None
    eligible_neighbourhoods = []
    
    for depth_str, neighbourhoods in sorted(data["neighborhoods"].items(), key=lambda item: int(item[0])):
        depth = int(depth_str)
        
        # Skip depth 0
        if depth == 0:
            continue
        
        eligible_neighbourhoods.clear()
        
        for neighbourhood_bin, count in sorted(neighbourhoods.items(), key=lambda item: int(item[1])):
            neighbourhood_bin = neighbourhood_bin[2:]
            if set(neighbourhood_bin) <= {'0', '1'} and count < 4:
                eligible_neighbourhoods.append(int(neighbourhood_bin, 2))
        
        if len(eligible_neighbourhoods) > 0:
            chosen_depth = depth
            break
    
    if chosen_depth is not None:
        chosen_neighbourhood = random.choice(eligible_neighbourhoods)
        return chosen_depth, chosen_neighbourhood
    else:
        return None, None


@app.route('/generate_wallet', methods=['GET'])
def generate_wallet():
    neighbourhood = request.args.get('n')
    depth = request.args.get('d')
    password = request.args.get('p', secrets.token_urlsafe(24))  # Generate a random password if not provided

    if neighbourhood is None or depth is None:
        depth, neighbourhood = find_lowest_neighbourhood()
        if depth is None or neighbourhood is None:
            return jsonify({'error': 'No suitable neighbourhood found.'}), 400
   
    radius = 3
    num_processes = int(os.cpu_count() * 0.80)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(generate_wallet_async(depth, neighbourhood, radius, num_processes))

    if result:
        wallet = result[0]
        encrypted_private_key = encrypt_private_key(wallet['private_key'], password)

        # Prepare the response JSON
        response_data = {
            'answer': 'Wallet generated by sniperbee.',
            'depth': depth,
            'neighbourhood': neighbourhood,
            'ethereum_address': wallet['ethereum_address'],
            'password': password,
            'wallet_json': encrypted_private_key
        }

        return jsonify(response_data)
    else:
        return jsonify({'error': 'No valid wallet found.'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

