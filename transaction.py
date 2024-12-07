import time
from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import overwrite_dataclass

# We are using a custom dataclass implementation.
dataclass = overwrite_dataclass(dataclass)

@dataclass(msg_id=1)  # The value 1 identifies this message and must be unique per community.
class Transaction:
    """ Represents a basic transaction. """
    sender: str
    receiver: str
    amount: int
    message: str
    nonce: int = 1
    ts: int = 0

    def __init__(self, sender: str, receiver: str, amount: int, nonce: int = 1, ts: int = None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.nonce = nonce
        self.ts = ts if ts is not None else int(time.time())

@dataclass(msg_id=2)  # The value 2 identifies this message and must be unique per community.
class SignedTransaction:
    """ Represents a signed transaction including a signature and public key. """
    transaction: Transaction
    signature: str
    public_key: str