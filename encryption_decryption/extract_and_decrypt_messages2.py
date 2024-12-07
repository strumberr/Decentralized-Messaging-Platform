import json
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import b64decode

class bcolors:
    ONTRANSACTION = "\033[95m"
    OKSIGNATURE = "\033[92m"
    BADSIGNATURE = "\033[91m"

    ONBLOCKMESSAGE = "\033[94m"
    OKBLOCK = "\033[92m"

    WARNING = "\033[93m"
    ERROR = "\033[91m"


def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def decrypt_message(encrypted_message, private_key):
    encrypted_message_bytes = b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

def extract_and_decrypt_messages(file_path, sender_public_key, receiver_private_key):
    messages_thread = []

    with open(file_path, 'r') as file:
        block_data = json.load(file)

        for block in block_data:
            try:
                transactions = json.loads(block["transaction_tx"])
                # print(f"Transatitionne1: {transactions}")
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in block: {e}")
                continue
            
            
            for transaction in transactions:
                
                decoded_sender_public_key = b64decode(transaction.get("sender")).decode('utf-8')

                if isinstance(transaction, dict) and decoded_sender_public_key == sender_public_key:
                    try:
                        decrypted_message = decrypt_message(transaction["message"], receiver_private_key)
                    except Exception as e:
                        print(f"Error decrypting message in block: {e}")
                        continue

                    messages_thread.append({
                        "timestamp": transaction["ts"],
                        "sender": transaction["sender"],
                        "receiver": transaction["receiver"],
                        "message": decrypted_message,
                    })
                    
                print(f"Decrypted message: {transaction}")

    # Sort messages by timestamp
    if messages_thread:
        messages_thread = sorted(messages_thread, key=lambda x: x["timestamp"])

    return messages_thread

def main():
    # parser = argparse.ArgumentParser(description="Extract and decrypt messages from a JSON block file for a specific sender public key.")
    # parser.add_argument("file_path", type=str, help="Path to the JSON block file.")
    # parser.add_argument("sender_public_key_file", type=str, help="File containing the sender's public key in PEM format.")
    # parser.add_argument("receiver_private_key_file", type=str, help="File containing the receiver's private key in PEM format.")
    
    # args = parser.parse_args()

    # sender_public_key = load_public_key(args.sender_public_key_file).public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # ).decode('utf-8')
    # receiver_private_key = load_private_key(args.receiver_private_key_file)
    
    # load sender_public_key from file
    with open("sender_public_key.pem", "rb") as file:
        sender_public_key = serialization.load_pem_public_key(file.read()).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
    # load receiver_private_key from file
    with open("receiver_private_key.pem", "rb") as file:
        receiver_private_key = serialization.load_pem_private_key(file.read(), password=None)
        
    
    messages_thread = extract_and_decrypt_messages("blocks.json", sender_public_key, receiver_private_key)

    # messages_thread = extract_and_decrypt_messages("blocks.json", sender_public_key, receiver_private_key)

    if messages_thread:
        for msg in messages_thread:
            print(bcolors.OKBLOCK + f"Timestamp: {msg['timestamp']}")
            print(bcolors.OKSIGNATURE + f"Sender: {msg['sender']}")
            print(bcolors.OKSIGNATURE + f"Receiver: {msg['receiver']}")
            print(bcolors.OKSIGNATURE + f"Message: {msg['message']}")
        print(bcolors.OKSIGNATURE + "\n")

if __name__ == "__main__":
    main()
