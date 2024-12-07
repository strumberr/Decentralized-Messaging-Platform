from email import message
import json
import time
from base64 import b64encode, b64decode
from collections import defaultdict
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.types import Peer
import asyncio
import os
import pickle

from transaction import Transaction, SignedTransaction, ResponseBlock, RequestBlock
from block import BlockMessage, Blockchain
from merkle_tree import MerkleTree
from hashlib import sha256
from pathlib import Path


import asyncio

    
class bcolors:
    ONTRANSACTION = "\033[95m"
    OKSIGNATURE = "\033[92m"
    BADSIGNATURE = "\033[91m"

    ONBLOCKMESSAGE = "\033[94m"
    OKBLOCK = "\033[92m"

    WARNING = "\033[93m"
    ERROR = "\033[91m"


class ValidatorCommunity(Community):
    community_id = b"harbourspaceuniverse"

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.executed_checks = 0
        self.balances = defaultdict(lambda: 1000)
        self.pending_txs = []
        self.saved_txs_hashes = {}
        self.finalized_txs = []
        self.current_block_txs = []
        self.merkle_tree = MerkleTree()
        self.add_message_handler(SignedTransaction, self.on_transaction)
        self.add_message_handler(BlockMessage, self.on_block_message)
        self.add_message_handler(RequestBlock, self.on_block_request)
        self.blocks_directory = "/Users/ginoasuncion/Projects/blockchain-class-group-activity/lab-template/verified_blocks"

        self.miner_address = b64encode(self.my_peer.public_key.key_to_bin()).decode("utf-8")
        self.mempool = []
        self.node_id = 0
        self.difficulty_target = 3
        self.block_size = 3
        self.active_mining = False
        self.stop_mining_event = asyncio.Event()  # Event to stop mining
        
    async def started(self, node_id) -> None:
        # self.register_task("check_transactions", self.check_transactions, interval=1.0, delay=1.0)
        self.node_id = node_id
        print(f"Node ID: {self.node_id}")

        # initialize Block class
        self.blockchain = Blockchain(node_id, self.difficulty_target)
        self.blockchain.community = self  # Link to the community

    def serialize_transaction(self, tx: Transaction) -> bytes:
        return json.dumps(tx.__dict__, sort_keys=True).encode()

    def deserialize_transaction(self, data: bytes) -> Transaction:
        return Transaction(**json.loads(data))

    def node_id_from_peer(self, peer: Peer) -> int:
        return int.from_bytes(peer.public_key.key_to_bin()[:4], byteorder="big")

    def generate_tx_id(self, tx: Transaction):
        return hash((tx.sender, tx.receiver, tx.amount, tx.nonce, tx.ts))

    def verify_signature(self, payload, tx):
        # Verify the signature of the transaction
        try:
            valid_signature = self.crypto.is_valid_signature(
                self.crypto.key_from_public_bin(b64decode(payload.public_key)),
                self.serialize_transaction(tx),
                b64decode(payload.signature),
            )
            if not valid_signature:
                print(bcolors.BADSIGNATURE + f"Invalid signature for transaction {tx.nonce} from {tx.sender}")
                return False
        except Exception as e:
            print(bcolors.ERROR + f"Error verifying signature: {e}")
            return False

        print(bcolors.OKSIGNATURE + f"Valid transaction {tx.nonce} from {tx.sender}")
        return True

    def verify_block_transactions(self, block):
        transactions = json.loads(block.transaction_tx)
        for tx_data in transactions:
            tx = Transaction(**tx_data['transaction'])
            signed_tx = SignedTransaction(transaction=tx, signature=tx_data['signature'], public_key=tx_data['public_key'])
            if not self.verify_signature(signed_tx, tx):
                return False
        return True


    async def broadcast_block(self, block):
        block_message = BlockMessage(
            timestamp=block.timestamp,
            difficulty=block.difficulty,
            nonce=block.nonce,
            prev_hash=block.prev_hash,
            merkle_root=block.merkle_root,
            transaction_tx=block.transaction_tx,
            block_hash=block.block_hash
        )
        
        for peer in self.get_peers():
            self.ez_send(peer, block_message)

        print(f"Broadcasted block {block.block_hash} to peers")

    @lazy_wrapper(SignedTransaction)
    async def on_transaction(self, peer: Peer, payload: SignedTransaction) -> None:
        """Handle incoming transactions from peers."""

        tx: Transaction = payload.transaction

        # Check if the transaction has already been received
        if self.generate_tx_id(tx) in self.saved_txs_hashes:
            print(bcolors.WARNING + f"Transaction {tx.nonce} already received")
            return

        self.saved_txs_hashes[self.generate_tx_id(tx)] = True
        print(bcolors.ONTRANSACTION + f"Received transaction {tx.nonce} from {tx.sender} in a validator community")

        # Verify the signature of the transaction
        if self.verify_signature(payload, tx):
            # add the transaction to the mempool
            self.mempool.append(tx)

        # if the mempool has at least 3 transactions, create a block and pass it to mine_block
        if len(self.mempool) >= self.block_size:
            
            if self.blockchain.active_mining:
                print("Mining in progress")
                return
            
            # pick 3 transactions from the mempool
            self.current_block_txs = self.mempool[:self.block_size]
            
            # Create the block
            block = await self.blockchain.create_new_block(self.current_block_txs)
            
            # Remove the block's transactions from the mempool
            self.remove_transactions_from_mempool(block)
            
            # Add the block to the blockchain
            self.blockchain.chain.append(block)
            print(f"Added block {block.block_hash} to the blockchain")

            # Save the block to a file
            self.save_block_to_file(block)

            for peer in self.get_peers():
                self.ez_send(peer, payload)

    def compute_hash(self, block, nonce):
        block_string = f'{block.timestamp}{block.difficulty}{nonce}{block.prev_hash}{block.merkle_root}{block.transaction_tx}'
        return sha256(block_string.encode()).hexdigest()
    
    

    def create_merkle_root(self, transactions):
        """ Create a Merkle root from a list of signed transactions. """
        # print(f"Transatitionne1: {transactions}")
        
        transactions = self.format_merkle_root(transactions)

        tree = MerkleTree()
        for signed_tx in transactions:
            tx_string = json.dumps(signed_tx.__dict__, default=lambda o: o.__dict__)
            tree.add_leaf(tx_string)
            
        return tree.get_root()
    

    def format_merkle_root(self, transactions):
        """ Create a Merkle root from a list of signed transactions. """
        # Decode the JSON string into a list of dictionaries
        transactions_list = json.loads(transactions)
        # print(f"Transactions List: {transactions_list}")
        
        reconstructed_transactions = []
        for tx_data in transactions_list:
            # Recreate the transaction object
            tx = Transaction(
                sender=tx_data['sender'],
                receiver=tx_data['receiver'],
                amount=tx_data['amount'],
                nonce=tx_data['nonce'],
                ts=tx_data['ts'],
                message=tx_data['message']
            )
            
            reconstructed_transactions.append(tx)

        # print(f"Transatitionne2: {reconstructed_transactions}")
        
        return reconstructed_transactions

    def stop_mining(self):
        self.active_mining = False  # Set the flag to false to indicate that mining should stop

    def remove_transactions_from_mempool(self, block):
        transactions = json.loads(block.transaction_tx)
        tx_ids_to_remove = {self.generate_tx_id(Transaction(**tx_data)) for tx_data in transactions}
        self.mempool = [tx for tx in self.mempool if self.generate_tx_id(tx) not in tx_ids_to_remove]
        
    def save_block_to_file(self, block):
        # Ensure the directory exists
        directory = "verified_blocks"
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Create the file path
        filename = f"{directory}/block_{block.timestamp}.json"

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

    @lazy_wrapper(BlockMessage)
    async def on_block_message(self, peer: Peer, payload: BlockMessage) -> None:
        block = BlockMessage(
            timestamp=payload.timestamp,
            difficulty=payload.difficulty,
            nonce=payload.nonce,
            prev_hash=payload.prev_hash,
            merkle_root=payload.merkle_root,
            transaction_tx=payload.transaction_tx,
            block_hash=payload.block_hash
        )


        print(block)
        
        # Verify the block's proof of work by checking if the hash starts with the required number of zeros
        if not block.block_hash.startswith('0' * self.difficulty_target):
            print(bcolors.ERROR + f"Invalid proof of work for block {block.block_hash}")
            return
        else:
            print(bcolors.OKBLOCK + f"Valid proof of work for block {block.block_hash}")
        
        transactions_received = block.transaction_tx
        if self.create_merkle_root(transactions_received) != block.merkle_root:
            print(bcolors.ERROR + f"Invalid merkle root for block {block.block_hash}")
            return
        else:
            print(bcolors.OKBLOCK + f"Valid merkle root for block {block.block_hash}")
            
        
        # verify and compare the block hash with the computed hash
        if block.block_hash != self.compute_hash(block, block.nonce):
            print(bcolors.ERROR + f"Invalid block hash for block {block.block_hash}")
            return
        else:
            print(bcolors.OKBLOCK + f"Valid block hash for block {block.block_hash}")
        
       
        # Stop mining if a valid block is received
        self.stop_mining()

        # Remove the block's transactions from the mempool
        self.remove_transactions_from_mempool(block)

        # Add the block to the blockchain
        self.blockchain.chain.append(block)
        print(f"Added block {block.block_hash} received from peer {peer}")

        # Save the block to a file
        self.save_block_to_file(block)


    @lazy_wrapper(RequestBlock)
    async def on_block_request(self, peer: Peer, payload: RequestBlock) -> None:
        
        for block_file in Path(self.blocks_directory).glob("*.json"):
            with open(block_file, 'r') as f:
                block_text = f.read()
                blocks_json = json.dumps(block_text)
                self.ez_send(peer, ResponseBlock(blockchain=blocks_json))
