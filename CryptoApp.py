import os
from base64 import b64encode, b64decode
from Crypto.Cipher import (
    AES, Blowfish, ARC4, DES, DES3, 
    CAST, ChaCha20
)
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from extended_ciphers import create_cipher, GOST28147, Twofish, XTEA

class CryptoApp:
    def __init__(self):
        # Available algorithms (key: display name, value: implementation status)
        self.algorithms = {
            '1': ('AES', True),
            '2': ('ARC4', True),
            '3': ('Blowfish', True),
            '4': ('Blowfish-compat', False),
            '5': ('CAST-128', True),
            '6': ('CAST-256', False),
            '7': ('DES', True),
            '8': ('TripleDES', True),
            '9': ('GOST', True),
            '10': ('Rijndael-128', True),
            '11': ('Rijndael-192', False),
            '12': ('Rijndael-256', False),
            '13': ('Twofish', True),
            '14': ('Serpent', False),
            '15': ('XTEA', True),
            '16': ('LOKI97', False),
            '17': ('SAFER+', False),
            '18': ('WAKE', False),
            '19': ('Enigma', False),
            '20': ('RC2', False)
        }
        
        self.modes = {
            '1': 'CBC',
            '2': 'CFB',
            '3': 'CTR',
            '4': 'OFB',
            '5': 'ECB',
            '6': 'STREAM'
        }
        
        self.encodings = {
            '1': 'Base64',
            '2': 'Hex'
        }
        
        self.clear_screen()
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def get_cipher(self, algo, mode, key, iv=None):
        """Create cipher object or return None if not available"""
        try:
            if algo in ['GOST', 'Twofish', 'XTEA', 'Rijndael-128']:
                return create_cipher(algo.lower(), key, mode, iv)
            elif algo == 'AES':
                return AES.new(key, self._get_mode('AES', mode), iv=iv)
            elif algo == 'ARC4':
                if mode != 'STREAM':
                    print("⚠️ ARC4 only supports STREAM mode. Using STREAM.")
                return ARC4.new(key)
            elif algo == 'Blowfish':
                return Blowfish.new(key, self._get_mode('Blowfish', mode), iv=iv)
            elif algo == 'CAST-128':
                return CAST.new(key, CAST.MODE_CBC, iv=iv) if mode == 'CBC' else None
            elif algo == 'DES':
                return DES.new(key, self._get_mode('DES', mode), iv=iv)
            elif algo == 'TripleDES':
                return DES3.new(key, self._get_mode('DES', mode), iv=iv)
            elif algo == 'ChaCha20':
                if mode != 'STREAM':
                    print("⚠️ ChaCha20 only supports STREAM mode. Using STREAM.")
                return ChaCha20.new(key=key, nonce=iv[:12])
            return None
        except Exception as e:
            print(f"⚠️ Error creating cipher: {str(e)}")
            return None
    
    def _get_mode(self, algo, mode):
        """Get mode constant for specific algorithm"""
        mode_maps = {
            'AES': {
                'CBC': AES.MODE_CBC,
                'CFB': AES.MODE_CFB,
                'CTR': AES.MODE_CTR,
                'OFB': AES.MODE_OFB,
                'ECB': AES.MODE_ECB
            },
            'Blowfish': {
                'CBC': Blowfish.MODE_CBC,
                'CFB': Blowfish.MODE_CFB,
                'OFB': Blowfish.MODE_OFB,
                'ECB': Blowfish.MODE_ECB
            },
            'DES': {
                'CBC': DES.MODE_CBC,
                'CFB': DES.MODE_CFB,
                'OFB': DES.MODE_OFB,
                'ECB': DES.MODE_ECB
            },
            'GOST': {
                'CBC': 'CBC',
                'ECB': 'ECB'
            },
            'Twofish': {
                'CBC': 'CBC',
                'ECB': 'ECB'
            },
            'XTEA': {
                'CBC': 'CBC',
                'ECB': 'ECB'
            },
            'Rijndael-128': {
                'CBC': 'CBC',
                'ECB': 'ECB'
            }
        }
        return mode_maps.get(algo, {}).get(mode, None)
    
    def get_iv_size(self, algo):
        """Get appropriate IV size for algorithm"""
        sizes = {
            'AES': 16,
            'Blowfish': 8,
            'CAST-128': 8,
            'DES': 8,
            'TripleDES': 8,
            'ChaCha20': 12,
            'GOST': 8,
            'Twofish': 16,
            'XTEA': 8,
            'Rijndael-128': 16
        }
        return sizes.get(algo, 16)  # Default to 16 bytes
    
    def pad_key(self, key, algo):
        """Adjust key length according to algorithm requirements"""
        key_sizes = {
            'AES': 16,  # 16, 24, or 32 for AES-128, AES-192, AES-256
            'ARC4': 256,  # 1-256 bytes
            'Blowfish': 16,  # 4-56 bytes
            'CAST-128': 16,
            'DES': 8,
            'TripleDES': 24,  # 16 or 24 bytes
            'GOST': 32,
            'Twofish': 32,  # 16, 24, or 32
            'XTEA': 16,
            'Rijndael-128': 16
        }
        
        target_length = key_sizes.get(algo, 32)
        if algo == 'ARC4':
            return key[:256]  # ARC4 can use any length up to 256 bytes
        elif algo == 'Twofish':
            # Twofish supports 128, 192, or 256-bit keys
            if len(key) >= 32:
                return key[:32]
            elif len(key) >= 24:
                return key[:24]
            else:
                return key[:16]
        return key.ljust(target_length, b'\0')[:target_length]
    
    # ... (rest of the methods remain the same as in your original code)

    def display_menu(self, title, options, show_coming_soon=False):
        """Display menu with optional 'Coming Soon' markers"""
        print(f"\n--- {title.upper()} ---")
        for num, value in options.items():
            if isinstance(value, tuple):  # For algorithms dictionary
                name, available = value
                if show_coming_soon:
                    status = "" if available else " (Coming Soon)"
                    print(f"{num}. {name}{status}")
                else:
                    print(f"{num}. {name}")
            else:  # For modes and encodings dictionaries
                print(f"{num}. {value}")
        print()

    def get_user_choice(self, options, prompt):
        """Get validated user choice"""
        while True:
            choice = input(prompt).strip()
            if choice in options:
                if isinstance(options[choice], tuple):
                    name, available = options[choice]
                    if not available:
                        print("\n🚧 This algorithm is coming soon!")
                        input("Press Enter to continue...")
                        return None
                    return name
                return options[choice]
            print("Invalid choice. Please try again.")

    def encrypt(self):
        """Encryption process"""
        print("\n=== ENCRYPTION ===")
        key = input("Enter key: ").encode()
        plaintext = input("Enter plaintext: ").replace("\\n", "\n").encode()
        
        self.display_menu("ALGORITHMS", self.algorithms, show_coming_soon=True)
        algo = self.get_user_choice(self.algorithms, "Select algorithm: ")
        if algo is None:
            return
        
        self.display_menu("MODES", self.modes)
        mode = self.get_user_choice(self.modes, "Select mode: ")
        
        self.display_menu("ENCODINGS", self.encodings)
        encoding = self.get_user_choice(self.encodings, "Select encoding: ")
        
        iv = get_random_bytes(self.get_iv_size(algo)) if mode not in ['ECB', 'STREAM'] else None
        padded_key = self.pad_key(key, algo)
        
        cipher = self.get_cipher(algo, mode, padded_key, iv)
        if cipher is None:
            print("\n❌ Selected algorithm/mode combination is not available")
            return
        
        try:
            ciphertext = cipher.encrypt(pad(plaintext, cipher.block_size if hasattr(cipher, 'block_size') else 8))
            
            self.clear_screen()
            print("\n✅ Encryption successful!")
            
            output = iv + ciphertext if iv is not None else ciphertext
            
            if encoding == 'Base64':
                result = b64encode(output).decode()
            else:
                result = output.hex()
            
            print(f"\nAlgorithm: {algo}")
            print(f"Mode: {mode}")
            print(f"Key: {key.decode()}")
            if iv is not None:
                print(f"IV: {iv.hex()}")
            print(f"\nResult ({encoding}):\n{result}")
            
        except Exception as e:
            print(f"\n❌ Encryption failed: {str(e)}")

    def decrypt(self):
        """Decryption process"""
        print("\n=== DECRYPTION ===")
        key = input("Enter key: ").encode()
        ciphertext = input("Enter ciphertext: ").strip()
        
        self.display_menu("ALGORITHMS", self.algorithms, show_coming_soon=True)
        algo = self.get_user_choice(self.algorithms, "Select algorithm: ")
        if algo is None:
            return
        
        self.display_menu("MODES", self.modes)
        mode = self.get_user_choice(self.modes, "Select mode: ")
        
        self.display_menu("ENCODINGS", self.encodings)
        encoding = self.get_user_choice(self.encodings, "Select encoding: ")
        
        try:
            if encoding == 'Base64':
                data = b64decode(ciphertext)
            else:
                data = bytes.fromhex(ciphertext)
            
            iv_size = self.get_iv_size(algo) if mode not in ['ECB', 'STREAM'] else 0
            iv = data[:iv_size] if iv_size > 0 else None
            actual_ciphertext = data[iv_size:]
            
            padded_key = self.pad_key(key, algo)
            cipher = self.get_cipher(algo, mode, padded_key, iv)
            
            if cipher is None:
                print("\n❌ Selected algorithm/mode combination is not available")
                return
            
            plaintext = unpad(
                cipher.decrypt(actual_ciphertext),
                cipher.block_size if hasattr(cipher, 'block_size') else 8
            )
            
            self.clear_screen()
            print("\n✅ Decryption successful!")
            print(f"\nAlgorithm: {algo}")
            print(f"Mode: {mode}")
            print(f"\nResult:\n{plaintext.decode()}")
            
        except Exception as e:
            print(f"\n❌ Decryption failed: {str(e)}")

    def main_menu(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            print("=== CRYPTOGRAPHY TOOL ===")
            print("1. Encrypt")
            print("2. Decrypt")
            print("3. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.encrypt()
            elif choice == '2':
                self.decrypt()
            elif choice == '3':
                print("\nGoodbye!")
                break
            else:
                print("Invalid option. Please try again.")
            
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    app = CryptoApp()
    app.main_menu()
