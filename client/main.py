from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import b64encode, b64decode
import json
import random
import time
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.util import run_forever
from ipv8_service import IPv8
from asyncio import run, sleep
from ipv8.community import Community, CommunitySettings
from ipv8.types import Peer
from transaction import Transaction, SignedTransaction

builder = ConfigBuilder().clear_keys().clear_overlays()

class bcolors:
    SENDTRANSACTION = "\033[94m"
    ERROR = "\033[91m"

def encrypt_message(message: str, public_key_pem: bytes) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b64encode(encrypted_message).decode('utf-8')

class MyCommunity(Community):
    community_id = b"harbourspaceuniverse"

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.counter = 1
        self.max_messages = 3
        self.sender_private_key = None
        self.receiver = None
        self.amount = None
        self.message = None
        self.sender_public_key = None
        self.receiver_public_key = None

    def started(self, sender_private_key, sender_public_key, receiver, amount, message, builder) -> None:
        self.register_task(
            "create_transaction", self.create_transaction, interval=1.0, delay=3.0
        )
        self.sender_private_key = sender_private_key
        self.receiver_public_key = receiver
        print(f"Receiver Type: {type(receiver)}")
        print(f"Sender Type: {type(sender_public_key)}")
        self.amount = amount
        self.message = message
        self.sender_public_key = sender_public_key
        self.builder = builder

    def serialize_transaction(self, tx: Transaction) -> bytes:
        return json.dumps(tx.__dict__, sort_keys=True).encode()

    def deserialize_transaction(self, data: bytes) -> Transaction:
        tx_dict = json.loads(data)
        tx_dict['message'] = b64decode(tx_dict['message'])  # Decode the base64 string back to bytes
        return Transaction(**tx_dict)

    def node_id_from_peer(self, peer: Peer) -> int:
        return int.from_bytes(peer.public_key.key_to_bin()[:4], byteorder="big")

    async def create_transaction(self) -> None:
        print(f"Connected to: {len(self.get_peers())}")

        encrypted_message = encrypt_message(self.message, self.receiver_public_key)

        tx = Transaction(
            sender=b64encode(self.sender_public_key).decode("utf-8"),
            receiver=b64encode(self.receiver_public_key).decode("utf-8"),
            amount=self.amount,
            nonce=self.counter,
            ts=int(time.time()),
            message=encrypted_message  # Use the base64 encoded encrypted message
        )

        print(f"Transaction: {tx}")

        tx_data = self.serialize_transaction(tx)

        print(f"Private key: {self.my_peer.key}")

        if not self.get_peers():
            print(
                bcolors.ERROR
                + f"[Node {self.my_peer.mid}] No peers available to send a transaction."
            )
            return "No peers available to send a transaction."

        peer = random.choice(self.get_peers())
        
        signature = b64encode(
            self.crypto.create_signature(self.my_peer.key, tx_data)
        ).decode("utf-8")

        signed_tx = SignedTransaction(
            tx,
            signature,
            b64encode(self.my_peer.public_key.key_to_bin()).decode("utf-8"),
        )

        self.counter += 1
        self.ez_send(peer, signed_tx)

        self.cancel_pending_task("create_transaction")

async def start_communities(sender_private_key, sender_public_key, receiver, amount, message) -> None:
    builder.add_key("my peer", "medium", f"ec1.pem")
    
    builder.add_overlay("MyCommunity", "my peer",
                        [WalkerDefinition(Strategy.RandomWalk,
                                          20, {'timeout': 1.0})],
                        default_bootstrap_defs, {}, [('started', 
                                                      sender_private_key, 
                                                      sender_public_key, 
                                                      receiver, amount, 
                                                      message,
                                                      builder)])

    ipv8 = IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity})
    
    await ipv8.start()
    await sleep(5)
    await ipv8.stop()

# sender_private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# sender_unencrypted_pem_private_key = sender_private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()
# )
# sender_pem_public_key = sender_private_key.public_key().public_bytes(
#   encoding=serialization.Encoding.PEM,
#   format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# save the keys to a file
# with open("sender_private_key.pem", "wb") as f:
#     f.write(sender_unencrypted_pem_private_key)
    
# with open("sender_public_key.pem", "wb") as f:
#     f.write(sender_pem_public_key)
    

# receiver_private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# receiver_unencrypted_pem_private_key = receiver_private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()
# )

# receiver_pem_public_key = receiver_private_key.public_key().public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )


# save the keys to a file
# with open("receiver_private_key.pem", "wb") as f:
#     f.write(receiver_unencrypted_pem_private_key)
    
# with open("receiver_public_key.pem", "wb") as f:
#     f.write(receiver_pem_public_key)
    


# use the keys from the files
# with open("sender_private_key.pem", "rb") as f:
#     sender_unencrypted_pem_private_key = f.read()
    
# with open("sender_public_key.pem", "rb") as f:
#     sender_pem_public_key = f.read()
    
# with open("receiver_private_key.pem", "rb") as f:
#     receiver_unencrypted_pem_private_key = f.read()
    
# with open("receiver_public_key.pem", "rb") as f:
#     receiver_pem_public_key = f.read()
    


# # print all the keys
# print(f"Sender Private Key: {sender_unencrypted_pem_private_key}")
# print(f"Sender Public Key: {sender_pem_public_key}")
# print(f"Receiver Private Key: {receiver_unencrypted_pem_private_key}")
# print(f"Receiver Public Key: {receiver_pem_public_key}")


# sender_private_key = sender_unencrypted_pem_private_key
# sender_public_key = sender_pem_public_key
# receiver_public_key = receiver_pem_public_key


# amount = 10
# message = "Boogers"

# for el in range(3):
#     run(start_communities(sender_private_key, sender_public_key, receiver_public_key, amount, message))
