import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key, private_key_file, public_key_file):
    with open(private_key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_key_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def main():
    sender_private_key, sender_public_key = generate_rsa_key_pair()
    receiver_private_key, receiver_public_key = generate_rsa_key_pair()

    save_keys(sender_private_key, sender_public_key, 'private_key_caesar.pem', 'public_key_caesar.pem')
    save_keys(receiver_private_key, receiver_public_key, 'private_key_storm.pem', 'public_key_storm.pem')

    print("Keys generated and saved to files:")

    print("Sender private key: sender_private_key.pem")
    print("Sender public key: sender_public_key.pem")
    print("Receiver private key: receiver_private_key.pem")
    print("Receiver public key: receiver_public_key.pem")

if __name__ == "__main__":
    main()

