import os
import json
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None)
    return private_key


def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key


def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        bytes.fromhex(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')


def extract_and_decrypt_messages(directory, sender_public_key, receiver_private_key):
    messages_thread = []

    # List all JSON files in the directory
    block_files = [f for f in os.listdir(directory) if f.endswith('.json')]

    for block_file in block_files:

        with open(os.path.join(directory, block_file), 'r') as file:
            block_data = json.load(file)

            try:
                transactions = json.loads(block_data["transaction_tx"])
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in file {block_file}: {e}")
                continue

            for transaction in transactions:
                if isinstance(transaction, dict) and transaction.get("sender_pem_public_key") == sender_public_key:
                    try:
                        decrypted_message = decrypt_message(
                            transaction["message"], receiver_private_key)
                    except Exception as e:
                        print(f"Error decrypting message in file {
                              block_file}: {e}")
                        continue

                    messages_thread.append({
                        "timestamp": transaction["ts"],
                        "sender": transaction["sender"],
                        "receiver": transaction["receiver"],
                        "message": decrypted_message,
                        "sender_pem_public_key": transaction["sender_pem_public_key"],
                        "receiver_pem_public_key": transaction["receiver_pem_public_key"]
                    })

    # Sort messages by timestamp
    if messages_thread:
        messages_thread = sorted(messages_thread, key=lambda x: x["timestamp"])

    return messages_thread


def main():
    parser = argparse.ArgumentParser(
        description="Extract and decrypt messages from JSON block files for a specific sender public key.")
    parser.add_argument("directory", type=str,
                        help="Directory containing the JSON block files.")
    parser.add_argument("sender_public_key_file", type=str,
                        help="File containing the sender's public key in PEM format.")
    parser.add_argument("receiver_private_key_file", type=str,
                        help="File containing the receiver's private key in PEM format.")

    args = parser.parse_args()

    sender_public_key = load_public_key(args.sender_public_key_file).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    receiver_private_key = load_private_key(args.receiver_private_key_file)

    messages_thread = extract_and_decrypt_messages(
        args.directory, sender_public_key, receiver_private_key)

    if messages_thread:
        for msg in messages_thread:
            print(Fore.YELLOW + f"Timestamp: {msg['timestamp']}")
            print(Fore.BLUE + f"Sender: {msg['sender']}")
            print(Fore.GREEN + f"Receiver: {msg['receiver']}")
            print(Fore.MAGENTA + f"Message: {msg['message']}")
            print(Fore.CYAN +
                  f"Sender Public Key: {msg['sender_pem_public_key']}")
            print(
                Fore.RED + f"Receiver Public Key: {msg['receiver_pem_public_key']}\n")
    else:
        print(Fore.RED + "No messages found for the specified sender public key.")


if __name__ == "__main__":
    main()
