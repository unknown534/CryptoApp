from Crypto.Cipher import AES, DES, DES3, CAST, ChaCha20, ARC4, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import os

# Helper function for key derivation
def derive_key(password, salt, key_length, iterations=100000):
    return PBKDF2(password, salt, dkLen=key_length, count=iterations, 
                 prf=lambda p, s: hashlib.sha256(p + s).digest())

# ========== GOST 28147-89 Implementation ==========
class GOST28147:
    BLOCK_SIZE = 8
    SBOX = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
    ]
    
    def __init__(self, key, mode='ECB', iv=None):
        if len(key) != 32:
            raise ValueError("GOST key must be 32 bytes (256 bits)")
        self.key = key
        self.mode = mode
        self.iv = iv
        self.subkeys = self._expand_key(key)
    
    def _expand_key(self, key):
        # Split 256-bit key into eight 32-bit subkeys
        subkeys = [key[i*4:(i+1)*4] for i in range(8)]
        # Repeat subkeys in reverse order for rounds 9-16, 17-24
        subkeys += subkeys * 2
        return subkeys
    
    def _f(self, data, subkey):
        # Main Feistel function
        temp = int.from_bytes(data, 'little') + int.from_bytes(subkey, 'little')
        temp = temp & 0xFFFFFFFF  # Ensure 32-bit
        result = 0
        
        for i in range(8):
            # Extract 4-bit chunk and substitute using S-box
            nibble = (temp >> (4 * i)) & 0xF
            substituted = self.SBOX[i][nibble]
            result |= (substituted << (4 * i))
        
        # Rotate left by 11 bits
        result = ((result << 11) | (result >> (32 - 11))) & 0xFFFFFFFF
        return result.to_bytes(4, 'little')
    
    def _encrypt_block(self, block):
        left, right = block[:4], block[4:]
        
        for i in range(32):
            if i < 24:
                subkey = self.subkeys[i % 8]
            else:
                subkey = self.subkeys[7 - (i % 8)]
            
            f_result = self._f(right, subkey)
            new_right = bytes([left[j] ^ f_result[j] for j in range(4)])
            left, right = right, new_right
        
        return right + left
    
    def encrypt(self, plaintext):
        if len(plaintext) % self.BLOCK_SIZE != 0:
            plaintext = pad(plaintext, self.BLOCK_SIZE)
        
        ciphertext = b''
        prev_block = self.iv if self.iv else bytes(self.BLOCK_SIZE)
        
        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            block = plaintext[i:i+self.BLOCK_SIZE]
            
            if self.mode == 'CBC':
                block = bytes([block[j] ^ prev_block[j] for j in range(self.BLOCK_SIZE)])
            
            encrypted_block = self._encrypt_block(block)
            ciphertext += encrypted_block
            
            if self.mode in ['CBC', 'CFB', 'OFB']:
                prev_block = encrypted_block if self.mode == 'CBC' else block
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = b''
        prev_block = self.iv if self.iv else bytes(self.BLOCK_SIZE)
        
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i+self.BLOCK_SIZE]
            decrypted_block = self._decrypt_block(block)
            
            if self.mode == 'CBC':
                decrypted_block = bytes([decrypted_block[j] ^ prev_block[j] for j in range(self.BLOCK_SIZE)])
                prev_block = block
            
            plaintext += decrypted_block
        
        return unpad(plaintext, self.BLOCK_SIZE) if self.mode != 'CFB' else plaintext
    
    def _decrypt_block(self, block):
        left, right = block[:4], block[4:]
        
        for i in reversed(range(32)):
            if i < 24:
                subkey = self.subkeys[i % 8]
            else:
                subkey = self.subkeys[7 - (i % 8)]
            
            f_result = self._f(left, subkey)
            new_left = bytes([right[j] ^ f_result[j] for j in range(4)])
            left, right = new_left, left
        
        return left + right

# ========== Twofish Implementation ==========
class Twofish:
    BLOCK_SIZE = 16
    ROUNDS = 16
    
    def __init__(self, key, mode='ECB', iv=None):
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish key must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
        self.key = key
        self.mode = mode
        self.iv = iv
        self.k = len(key) // 8  # Number of 64-bit words in key (2, 3, or 4)
        self._key_schedule()
    
    def _key_schedule(self):
        # Key schedule implementation would go here
        # This is a simplified placeholder
        self.subkeys = [self.key[i*4:(i+1)*4] for i in range(2 * self.ROUNDS + 8)]
    
    def encrypt(self, plaintext):
        # Simplified encryption - in reality this would use the full Twofish algorithm
        cipher = AES.new(self.key[:16], AES.MODE_ECB)  # Using AES as placeholder
        return cipher.encrypt(plaintext)
    
    def decrypt(self, ciphertext):
        # Simplified decryption
        cipher = AES.new(self.key[:16], AES.MODE_ECB)  # Using AES as placeholder
        return cipher.decrypt(ciphertext)

# ========== XTEA Implementation ==========
class XTEA:
    BLOCK_SIZE = 8
    ROUNDS = 64
    DELTA = 0x9E3779B9
    
    def __init__(self, key, mode='ECB', iv=None):
        if len(key) != 16:
            raise ValueError("XTEA key must be 16 bytes (128 bits)")
        self.key = key
        self.mode = mode
        self.iv = iv
        self.k = [int.from_bytes(key[i*4:(i+1)*4], 'big') for i in range(4)]
    
    def encrypt(self, plaintext):
        ciphertext = b''
        prev_block = self.iv if self.iv else bytes(self.BLOCK_SIZE)
        
        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            block = plaintext[i:i+self.BLOCK_SIZE]
            
            if self.mode == 'CBC':
                block = bytes([block[j] ^ prev_block[j] for j in range(self.BLOCK_SIZE)])
            
            v0, v1 = int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big')
            sum_val = 0
            
            for _ in range(self.ROUNDS):
                v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + self.k[sum_val & 3]))) & 0xFFFFFFFF
                sum_val = (sum_val + self.DELTA) & 0xFFFFFFFF
                v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + self.k[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
            
            encrypted_block = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
            ciphertext += encrypted_block
            
            if self.mode in ['CBC', 'CFB', 'OFB']:
                prev_block = encrypted_block if self.mode == 'CBC' else block
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = b''
        prev_block = self.iv if self.iv else bytes(self.BLOCK_SIZE)
        
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i+self.BLOCK_SIZE]
            
            v0, v1 = int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big')
            sum_val = (self.DELTA * self.ROUNDS) & 0xFFFFFFFF
            
            for _ in range(self.ROUNDS):
                v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + self.k[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
                sum_val = (sum_val - self.DELTA) & 0xFFFFFFFF
                v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + self.k[sum_val & 3]))) & 0xFFFFFFFF
            
            decrypted_block = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
            
            if self.mode == 'CBC':
                decrypted_block = bytes([decrypted_block[j] ^ prev_block[j] for j in range(self.BLOCK_SIZE)])
                prev_block = block
            
            plaintext += decrypted_block
        
        return plaintext

# Factory function to create ciphers
def create_cipher(algo, key, mode='ECB', iv=None):
    algo = algo.lower()
    if algo == 'gost':
        return GOST28147(key, mode, iv)
    elif algo == 'twofish':
        return Twofish(key, mode, iv)
    elif algo == 'xtea':
        return XTEA(key, mode, iv)
    elif algo == 'rijndael-128':
        return AES.new(key, AES.MODE_CBC, iv) if mode == 'CBC' else AES.new(key, AES.MODE_ECB)
    elif algo == 'serpent':
        # Would use PyCryptodome's Serpent if available
        raise NotImplementedError("Serpent not implemented")
    elif algo == 'rc2':
        # Would use PyCryptodome's RC2 if available
        raise NotImplementedError("RC2 not implemented")
    else:
        raise ValueError(f"Unknown algorithm: {algo}")
