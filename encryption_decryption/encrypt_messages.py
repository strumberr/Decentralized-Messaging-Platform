import os
import json
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def process_block_files(input_directory, output_directory, sender_private_key, sender_public_key, receiver_public_key):
    block_files = [f for f in os.listdir(input_directory) if f.endswith('.json')]

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    for block_file in block_files:
        with open(os.path.join(input_directory, block_file), 'r') as file:
            block_data = json.load(file)

            if block_file == 'genesis_block.json':
                # Copy the genesis block without encryption
                with open(os.path.join(output_directory, block_file), 'w') as output_file:
                    json.dump(block_data, output_file, indent=4)
                continue

            try:
                transactions = json.loads(block_data["transaction_tx"])
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in file {block_file}: {e}")
                continue

            for transaction in transactions:
                message = transaction["message"]
                encrypted_message = encrypt_message(message, receiver_public_key)
                transaction["message"] = encrypted_message.hex()
                transaction["sender_pem_public_key"] = sender_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                transaction["receiver_pem_public_key"] = receiver_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')

            block_data["transaction_tx"] = json.dumps(transactions)

        with open(os.path.join(output_directory, block_file), 'w') as file:
            json.dump(block_data, file, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Encrypt messages in JSON block files.")
    parser.add_argument("input_directory", type=str, help="Directory containing the input JSON block files.")
    parser.add_argument("output_directory", type=str, help="Directory to save the output JSON block files.")
    parser.add_argument("sender_private_key_file", type=str, help="File containing the sender's private key in PEM format.")
    parser.add_argument("sender_public_key_file", type=str, help="File containing the sender's public key in PEM format.")
    parser.add_argument("receiver_public_key_file", type=str, help="File containing the receiver's public key in PEM format.")

    args = parser.parse_args()

    sender_private_key = load_private_key(args.sender_private_key_file)
    sender_public_key = load_public_key(args.sender_public_key_file)
    receiver_public_key = load_public_key(args.receiver_public_key_file)

    process_block_files(args.input_directory, args.output_directory, sender_private_key, sender_public_key, receiver_public_key)

if __name__ == "__main__":
    main()
