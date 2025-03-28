from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Diffie-Hellman Key Exchange Simulation
class DiffieHellman:
    def __init__(self):
        self.private_keys = {}
    
    def generate_private_key(self, user):
        private_key = os.urandom(32)
        self.private_keys[user] = private_key
        return private_key
    
    def compute_shared_key(self, user1, user2):
        return base64.b64encode(hashlib.sha256(self.private_keys[user1] + self.private_keys[user2]).digest()).decode()

# RSA Encryption & Decryption
class RSAEncryption:
    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def encrypt(self, message, public_key):
        return public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, encrypted_message, private_key):
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

# AES-256-CBC Encryption
class AESEncryption:
    def encrypt(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_data = plaintext.ljust(32).encode()  # Simple padding
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()
    
    def decrypt(self, encrypted_message, key):
        data = base64.b64decode(encrypted_message)
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

# Key Revocation Mechanism
class KeyRevocation:
    revoked_keys = set()
    
    def revoke_key(self, user):
        self.revoked_keys.add(user)
        return f"Key for {user} revoked."
    
    def is_revoked(self, user):
        return user in self.revoked_keys

# Example Usage
if __name__ == "__main__":
    # Diffie-Hellman Example
    dh = DiffieHellman()
    alice_key = dh.generate_private_key("Alice")
    bob_key = dh.generate_private_key("Bob")
    shared_key = dh.compute_shared_key("Alice", "Bob")
    print(f"Shared Key: {shared_key}")
    
    # RSA Example
    rsa_enc = RSAEncryption()
    private_key, public_key = rsa_enc.generate_keys()
    encrypted_msg = rsa_enc.encrypt("Secure Data", public_key)
    decrypted_msg = rsa_enc.decrypt(encrypted_msg, private_key)
    print(f"RSA Decrypted Message: {decrypted_msg}")
    
    # AES Example
    aes = AESEncryption()
    aes_key = os.urandom(32)
    encrypted_aes = aes.encrypt("Hello, World!", aes_key)
    decrypted_aes = aes.decrypt(encrypted_aes, aes_key)
    print(f"AES Decrypted Message: {decrypted_aes.strip().decode()}")
    
    # Key Revocation Example
    revocation_manager = KeyRevocation()
    print(revocation_manager.revoke_key("Alice"))
    if revocation_manager.is_revoked("Alice"):
        print("Access Denied: Key is revoked.")
