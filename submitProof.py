import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import geth_poa_middleware  # Necessary for POA chains
from io import TextIOWrapper


def merkle_assignment():
    """
        The only modifications you need to make to this method are to assign
        your "random_leaf_index" and uncomment the last line when you are
        ready to attempt to claim a prime. You will need to complete the
        methods called by this method to generate the proof.
    """
    # Generate the list of primes as integers
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)

    # Create a version of the list of primes in bytes32 format
    leaves = convert_leaves(primes)

    # Build a Merkle tree using the bytes32 leaves as the Merkle tree's leaves
    tree = build_merkle(leaves)

    # Select a random leaf and create a proof for that leaf
    random_leaf_index = 6582 #TODO generate a random index from primes to claim (0 is already claimed)
    proof = prove_merkle(tree, random_leaf_index)

    # This is the same way the grader generates a challenge for sign_challenge()
    challenge = ''.join(random.choice(string.ascii_letters) for i in range(32))
    # Sign the challenge to prove to the grader you hold the account
    addr, sig = sign_challenge(challenge)

    if sign_challenge_verify(challenge, addr, sig):
        tx_hash = '0x'
        # TODO, when you are ready to attempt to claim a prime (and pay gas fees),
        #  complete this method and run your code with the following line un-commented
        tx_hash = send_signed_msg(proof, leaves[random_leaf_index])


def generate_primes(num_primes):
    """
    Generate the first num_primes prime numbers
    """
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    
    primes_list = []
    num = 2
    while len(primes_list) < num_primes:
        if is_prime(num):
            primes_list.append(num)
        num += 1
    return primes_list

def convert_leaves(primes_list):
    """
    Convert prime numbers to bytes32 format
    """
    bytes32_leaves = []
    for prime in primes_list:
        # Convert to bytes32 format using big-endian encoding
        bytes_val = prime.to_bytes(32, 'big')
        bytes32_leaves.append(bytes_val)
    return bytes32_leaves

def build_merkle(leaves):
    """
    Build a Merkle Tree from leaves
    """
    if not leaves:
        return []
    
    tree = [leaves]
    current_level = leaves
    
    # Continue building levels until we reach the root
    while len(current_level) > 1:
        next_level = []
        # Process pairs of nodes
        for i in range(0, len(current_level), 2):
            # If we have an odd number of elements, duplicate the last one
            if i + 1 >= len(current_level):
                next_level.append(hash_pair(current_level[i], current_level[i]))
            else:
                next_level.append(hash_pair(current_level[i], current_level[i + 1]))
        tree.append(next_level)
        current_level = next_level
    
    return tree

def prove_merkle(merkle_tree, random_indx):
    """
    Generate Merkle proof for a specific leaf
    """
    if not merkle_tree or random_indx >= len(merkle_tree[0]):
        return []
    
    proof = []
    current_idx = random_indx
    
    # Go through each level except the root
    for level in range(len(merkle_tree) - 1):
        current_level = merkle_tree[level]
        is_right = current_idx % 2 == 0
        
        # If current_idx is even, we need the next element
        # If it's odd, we need the previous element
        if is_right and current_idx + 1 < len(current_level):
            proof.append(current_level[current_idx + 1])
        elif not is_right:
            proof.append(current_level[current_idx - 1])
        else:
            # If we have an odd number of elements, use the current element
            proof.append(current_level[current_idx])
        
        # Update index for next level
        current_idx = current_idx // 2
    
    return proof

def sign_challenge(challenge):
    """
    Takes a challenge (string)
    Returns address, sig
    where address is an ethereum address and sig is a signature (in hex)
    """
    acct = get_account()
    
    # Create the message object
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    
    # Sign the message and get both address and signature
    signed_message = eth_account.Account.sign_message(eth_encoded_msg, private_key=acct.key)
    
    return acct.address, signed_message.signature.hex()

def send_signed_msg(proof, random_leaf):
    """
    Send transaction to claim a prime
    """
    chain = 'bsc'
    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)
    
    # Get contract instance
    contract = w3.eth.contract(address=address, abi=abi)
    
    # Build transaction
    nonce = w3.eth.get_transaction_count(acct.address)
    
    # Wrap the proof in a list if it's not already a list
    if not isinstance(proof, list):
        proof = [proof]
        
    # Prepare the transaction
    tx = {
        'chainId': w3.eth.chain_id,
        'nonce': nonce,
        'gas': 300000,
        'gasPrice': w3.eth.gas_price,
        'to': address,
        'value': 0,
        'data': contract.encodeABI('submit', args=[proof, random_leaf])
    }
    
    # Sign the transaction
    signed = w3.eth.account.sign_transaction(tx, acct.key)
    
    # Send the raw transaction
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)  # Note: using .raw_transaction instead of .rawTransaction
    
    # Wait for transaction receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    return tx_hash.hex()


# Helper functions that do not need to be modified
def connect_to(chain):
    """
        Takes a chain ('avax' or 'bsc') and returns a web3 instance
        connected to that chain.
    """
    if chain not in ['avax','bsc']:
        print(f"{chain} is not a valid option for 'connect_to()'")
        return None
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"  # AVAX C-chain testnet
    else:
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"  # BSC testnet
    w3 = Web3(Web3.HTTPProvider(api_url))
    # inject the poa compatibility middleware to the innermost layer
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    return w3


def get_account():
    """
        Returns an account object recovered from the secret key
        in "sk.txt"
    """
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath('sk.txt'), 'r') as f:
        sk = f.readline().rstrip()
    if sk[0:2] == "0x":
        sk = sk[2:]
    return eth_account.Account.from_key(sk)


def get_contract_info(chain):
    """
        Returns a contract address and contract abi from "contract_info.json"
        for the given chain
    """
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath("contract_info.json"), "r") as f:
        d = json.load(f)
        d = d[chain]
    return d['address'], d['abi']


def sign_challenge_verify(challenge, addr, sig):
    """
        Helper to verify signatures, verifies sign_challenge(challenge)
        the same way the grader will. No changes are needed for this method
    """
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)

    if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == addr:
        print(f"Success: signed the challenge {challenge} using address {addr}!")
        return True
    else:
        print(f"Failure: The signature does not verify!")
        print(f"signature = {sig}\naddress = {addr}\nchallenge = {challenge}")
        return False


def hash_pair(a, b):
    """
        The OpenZeppelin Merkle Tree Validator we use sorts the leaves
        https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol#L217
        So you must sort the leaves as well

        Also, hash functions like keccak are very sensitive to input encoding, so the solidity_keccak function is the function to use

        Another potential gotcha, if you have a prime number (as an int) bytes(prime) will *not* give you the byte representation of the integer prime
        Instead, you must call int.to_bytes(prime,'big').
    """
    if a < b:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [a, b])
    else:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [b, a])


if __name__ == "__main__":
    merkle_assignment()
