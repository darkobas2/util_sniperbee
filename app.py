from flask import Flask, request, jsonify
import asyncio
from concurrent.futures import ProcessPoolExecutor
import logging, os, secrets, json, requests, random, time
from datetime import datetime, timedelta
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
    current_time = time.time()
    neighborhoods_data = None
    update_needed = False

    if os.path.exists("neighborhoods.json"):
        with open("neighborhoods.json", "r") as file:
            neighborhoods_data = json.load(file)

            # Check if all depths are empty or if 30 minutes have passed since last update
            if all(not depth_data["neighbourhoods"] for depth_data in neighborhoods_data) or \
                    current_time - neighborhoods_data[0].get("last_update", 0) >= 30 * 60:
                update_needed = True

    if not neighborhoods_data or update_needed:
        response = requests.get("https://api.swarmscan.io/v1/network/neighborhoods")
        data = response.json()

        eligible_neighbourhoods = []

        for depth_str, neighbourhoods in data["neighborhoods"].items():
            depth = int(depth_str)

            if depth == 0:
                continue

            eligible_neighbourhoods_for_depth = []

            for neighbourhood_bin, count in neighbourhoods.items():
                neighbourhood_bin = neighbourhood_bin[2:]
                if set(neighbourhood_bin) <= {'0', '1'} and count < 4:
                    eligible_neighbourhoods_for_depth.append({
                        "neighbourhood": neighbourhood_bin,
                        "count": count
                    })

            if eligible_neighbourhoods_for_depth:
                eligible_neighbourhoods.append({
                    "depth": depth,
                    "neighbourhoods": eligible_neighbourhoods_for_depth
                })

        # Save the complete dict with eligible neighbourhoods
        neighborhoods_data = eligible_neighbourhoods
        neighborhoods_data[0]["last_update"] = current_time  # Update the last_update timestamp
        with open('neighborhoods.json', 'w') as json_file:
            json.dump(neighborhoods_data, json_file, indent=4)

    if neighborhoods_data:
        # Sort eligible neighbourhoods by depth
        neighborhoods_data.sort(key=lambda x: x["depth"])

        chosen_data = neighborhoods_data[0]  # Select the first depth
        chosen_depth = chosen_data["depth"]
        chosen_neighbourhood_data = random.choice(chosen_data["neighbourhoods"])
        chosen_neighbourhood = chosen_neighbourhood_data["neighbourhood"]
        update_neighbourhood_count(chosen_depth, chosen_neighbourhood)
        return chosen_depth, int(chosen_neighbourhood, 2)
    else:
        return None, None

def update_neighbourhood_count(chosen_depth, chosen_neighbourhood):
    if os.path.exists("neighborhoods.json"):
        with open("neighborhoods.json", "r") as file:
            neighborhood_data = json.load(file)
    else:
        neighborhood_data = []

    for depth_data in neighborhood_data:
        if depth_data["depth"] == chosen_depth:
            for neighbourhood_data in depth_data["neighbourhoods"]:
                if neighbourhood_data["neighbourhood"] == chosen_neighbourhood:
                    neighbourhood_data["count"] += 1
                    if neighbourhood_data["count"] >= 4:
                        depth_data["neighbourhoods"].remove(neighbourhood_data)
                        if len(depth_data["neighbourhoods"]) == 0:
                            neighborhood_data.remove(depth_data)
                    break

    with open('neighborhoods.json', 'w') as json_file:
        json.dump(neighborhood_data, json_file, indent=4)

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

