
from dataclasses import dataclass
from hashlib import sha256
import json
import time
import asyncio
from ipv8.messaging.payload_dataclass import overwrite_dataclass
from merkle_tree import MerkleTree
import os

# Custom dataclass implementation
dataclass = overwrite_dataclass(dataclass)

@dataclass(msg_id=3)  # Add a unique msg_id here
class BlockMessage:
    """ Represents a block message. """
    timestamp: int
    difficulty: int
    nonce: int
    prev_hash: str
    merkle_root: str
    transaction_tx: str
    block_hash: str

@dataclass
class Transaction:
    """ Represents a basic transaction. """
    sender: str
    receiver: str
    amount: int
    nonce: int = 1
    ts: int = 0

@dataclass
class SignedTransaction:
    """ Represents a signed transaction including a signature and public key. """
    transaction: Transaction
    signature: str
    public_key: str

class bcolors:
    ONTRANSACTION = "\033[95m"
    OKSIGNATURE = "\033[92m"
    BADSIGNATURE = "\033[91m"

    ONBLOCKMESSAGE = "\033[94m"
    OKBLOCK = "\033[92m"

    WARNING = "\033[93m"
    ERROR = "\033[91m"

class Blockchain:
    """ Manages the blockchain and its operations. """
    def __init__(self, node_id, difficulty_target):
        self.node_id = node_id
        self.difficulty_target = difficulty_target
        self.chain = [self.create_genesis_block()]
        self.active_mining = False
        self.community = None  # Will be set by ValidatorCommunity



    def create_merkle_root(self, transactions):
        """ Create a Merkle root from a list of signed transactions. """
        print(f"Transatitionne1: {transactions}")

        tree = MerkleTree()
        for signed_tx in transactions:
            tx_string = json.dumps(signed_tx.__dict__, default=lambda o: o.__dict__)
            tree.add_leaf(tx_string)
        return tree.get_root()
    
    def save_block_to_file(self, block):
        # Ensure the directory exists
        directory = "verified_blocks"
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Create the file path
        filename = f"{directory}/genesis_block.json"

        # Convert the block to a dictionary and then to a JSON string
        block_data = {
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "nonce": block.nonce,
            "prev_hash": block.prev_hash,
            "merkle_root": block.merkle_root,
            "transaction_tx": block.transaction_tx,
            "block_hash": block.block_hash
        }
        block_json = json.dumps(block_data, indent=4)

        # Write the block JSON to the file
        with open(filename, "w") as file:
            file.write(block_json)

        print(f"Saved block {block.block_hash} to file {filename}")
        

    def create_genesis_block(self):
        timestamp = int(time.time())
        difficulty = self.difficulty_target
        nonce = 0
        prev_hash = '0' * 64
        
        coinbase_tx = SignedTransaction(
            transaction=Transaction(sender="boss", receiver="0", amount=50, nonce=1, ts=timestamp),
            signature="coinbase_signature",
            public_key="coinbase_public_key"
        )
        
        transactions = [coinbase_tx]
        
        merkle_root = self.create_merkle_root(transactions)
        
        genesis_block = BlockMessage(
            timestamp = timestamp, 
            difficulty = difficulty, 
            nonce=75806, 
            prev_hash = prev_hash, 
            merkle_root = merkle_root, 
            transaction_tx=json.dumps(coinbase_tx.__dict__, default=lambda o: o.__dict__),
            block_hash="00006a347b0bd5ee6c51104c4ed936597371ad02a5f9be8db3ea41be1e963462"
        )
        
        self.save_block_to_file(genesis_block)

        # append the genesis block to the chain
        return genesis_block
    
    

    async def create_new_block(self, transactions):
        timestamp = int(time.time())
        nonce = 0
        prev_hash = self.chain[-1].block_hash
        merkle_root = self.create_merkle_root(transactions)
        
        # Convert transactions to a JSON serializable format
        transactions_json = [tx.__dict__ for tx in transactions]

        new_block = BlockMessage(timestamp = timestamp, difficulty = self.difficulty_target, nonce=nonce, 
            prev_hash = prev_hash, 
            merkle_root = merkle_root, 
            transaction_tx=json.dumps(transactions_json),
            block_hash="new_block_hash"
        )

        await self.mine_block(new_block)
        return new_block


    async def add_block(self, transactions):
        if len(transactions) % 3 != 0:
            raise ValueError("The number of transactions must be a multiple of 3.")
        
        for i in range(0, len(transactions), 3):
            batch = transactions[i:i+3]
            new_block = await self.create_new_block(batch)
            self.chain.append(new_block)
        return new_block
    
    def compute_hash(self, block, nonce):
        block_string = f'{block.timestamp}{block.difficulty}{nonce}{block.prev_hash}{block.merkle_root}{block.transaction_tx}'
        return sha256(block_string.encode()).hexdigest()

    async def mine_block(self, block):
        print(f"Starting mining block {block}")
        
        # Start a timer
        start_time = time.time()
        start_time2 = time.time()
        hashes_computed = 0
        current_nonce = 0
        
        target = '0' * self.difficulty_target
        
        while True:
            self.active_mining = True
            
            # Every 2 seconds, print the time elapsed and the number of hashes computed
            if time.time() - start_time > 2:
                print(f"Hashes computed: {hashes_computed}")
                print(f"Time elapsed: {time.time() - start_time2:.2f} seconds")
                start_time = time.time()
                
            hash_result = self.compute_hash(block, current_nonce)
            
            if hash_result.startswith(target):
                block.nonce = current_nonce
                block.block_hash = hash_result
                print(f"Block mined by miner {self.node_id} with hash {block.block_hash}")
                
                print(
                    f'{bcolors.OKBLOCK}------------------------------------\n'
                    f"{bcolors.OKBLOCK}Block mined by miner {self.node_id} with hash {block.block_hash}\n"
                    f'''
                    {bcolors.OKBLOCK}New Block:\n
                    {bcolors.OKBLOCK}Timestamp: {block.timestamp}\n
                    {bcolors.OKBLOCK}Difficulty: {block.difficulty}\n
                    {bcolors.OKBLOCK}Nonce: {block.nonce}\n
                    {bcolors.OKBLOCK}Previous Hash: {block.prev_hash}\n
                    {bcolors.OKBLOCK}Merkle Root: {block.merkle_root}\n
                    {bcolors.OKBLOCK}Transaction Body: {block.transaction_tx}\n
                    {bcolors.OKBLOCK}Hash: {block.block_hash}\n'''
                    f'{bcolors.OKBLOCK}------------------------------------\n'
                )      
                
                # Add the block to the chain
                self.chain.append(block)
                
                # Broadcast the block to peers
                await self.community.broadcast_block(block)
                
                self.active_mining = False
                return
            
            current_nonce += 1
            hashes_computed += 1
            await asyncio.sleep(0)
