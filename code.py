import hashlib
import os
import json
import base64
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ----------------------------
# Utility Functions
# ----------------------------
def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

def aes_encrypt(key, plaintext: str) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(key, ciphertext_b64: str) -> str:
    data = base64.b64decode(ciphertext_b64)
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# ----------------------------
# Blockchain Ledger
# ----------------------------
class Block:
    def __init__(self, index, timestamp, data, prev_hash=""):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        record = f"{self.index}{self.timestamp}{self.data}{self.prev_hash}"
        return sha256(record)

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")

    def add_block(self, data):
        prev_block = self.chain[-1]
        block = Block(len(self.chain), time.time(), data, prev_block.hash)
        self.chain.append(block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            curr, prev = self.chain[i], self.chain[i-1]
            if curr.hash != curr.calculate_hash():
                return False
            if curr.prev_hash != prev.hash:
                return False
        return True

# ----------------------------
# Identity Authentication System
# ----------------------------
class IdentityAuthSystem:
    def __init__(self):
        self.users = {}  # username -> {password_hash, public_key, private_key}
        self.revoked = set()  # revoked users
        self.blockchain = Blockchain()

    def register_user(self, username, password):
        if username in self.users:
            raise Exception("User already exists")
        # Generate RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        # Store credentials
        self.users[username] = {
            "password_hash": sha256(password),
            "private_key": private_key,
            "public_key": public_key,
            "aes_key": generate_aes_key()
        }
        self.blockchain.add_block(f"User {username} registered")
        print(f"[+] User '{username}' registered successfully.")

    def authenticate(self, username, password):
        if username not in self.users or username in self.revoked:
            print("[-] Authentication failed: user not found or revoked")
            return False
        user = self.users[username]
        if user["password_hash"] != sha256(password):
            print("[-] Authentication failed: incorrect password")
            return False
        # Digital signature challenge
        message = b"auth_challenge"
        signature = user["private_key"].sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        try:
            user["public_key"].verify(
                signature, message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            self.blockchain.add_block(f"User {username} authenticated")
            print(f"[+] Authentication successful for {username}")
            return True
        except Exception:
            print("[-] Digital signature verification failed")
            return False

    def encrypt_user_data(self, username, data: str):
        if username not in self.users:
            raise Exception("User not found")
        key = self.users[username]["aes_key"]
        ciphertext = aes_encrypt(key, data)
        self.blockchain.add_block(f"User {username} encrypted data")
        return ciphertext

    def decrypt_user_data(self, username, ciphertext: str):
        if username not in self.users:
            raise Exception("User not found")
        key = self.users[username]["aes_key"]
        return aes_decrypt(key, ciphertext)

    def revoke_user(self, username):
        self.revoked.add(username)
        self.blockchain.add_block(f"User {username} revoked")
        print(f"[!] User '{username}' has been revoked.")

# ----------------------------
# Demo Execution
# ----------------------------
if __name__ == "__main__":
    system = IdentityAuthSystem()

    # Register users
    system.register_user("alice", "password123")
    system.register_user("bob", "secure456")

    # Authenticate
    system.authenticate("alice", "password123")
    system.authenticate("bob", "wrongpass")

    # Encrypt/Decrypt data
    secret = "This is Alice's secret cloud file."
    encrypted = system.encrypt_user_data("alice", secret)
    print("[*] Encrypted:", encrypted)
    decrypted = system.decrypt_user_data("alice", encrypted)
    print("[*] Decrypted:", decrypted)

    # Revoke and test
    system.revoke_user("bob")
    system.authenticate("bob", "secure456")

    # Blockchain validation
    print("[*] Blockchain valid?", system.blockchain.is_valid())
    print("[*] Blockchain length:", len(system.blockchain.chain))




