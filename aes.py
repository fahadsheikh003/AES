from key_expansion import Key_Expansion
from constants import *
from utils import byte_substitution_matrix, bytes_to_string, construct_state_matrix, cyclic_left_shift_vector, cyclic_right_shift_vector, inverse_byte_substitution_matrix, mix_columns, state_matrix_to_bytes, xor_of_matrix, inverse_mix_columns, string_to_bytes
from padding import pad, unpad
from concurrent.futures import ThreadPoolExecutor
from secrets import token_bytes
import argparse
from os.path import exists

class AES(Key_Expansion):
    CBC = "CBC"
    ECB = "ECB"
    # Expanding keys and setting up rounds according to key size
    def __init__(self, key: str | bytes, mode: str = ECB) -> None:
        if len(key) == AES256[KEY_SIZE] // BYTE:
            super().__init__(key, AES256[INITIAL_QUADRANTS], AES256[BYTES_QUADRANT])
            self.rounds = AES256[ROUNDS]
        elif len(key) == AES192[KEY_SIZE] // BYTE:
            super().__init__(key, AES192[INITIAL_QUADRANTS], AES192[BYTES_QUADRANT])
            self.rounds = AES192[ROUNDS]
        elif len(key) == AES128[KEY_SIZE] // BYTE:
            super().__init__(key, AES128[INITIAL_QUADRANTS], AES128[BYTES_QUADRANT])
            self.rounds = AES128[ROUNDS]
        else:
            raise ValueError("Invalid key")
        
        self.mode = mode

    # private method to encrypt a block of 128-bit
    def __encrypt_block(self, plain_text: str | bytes) -> bytes:
        if len(plain_text) != BLOCK_SIZE_BYTES:
            raise ValueError("Invalid Plaintext")

        state_matrix = construct_state_matrix(plain_text)

        round_key = construct_state_matrix(self.keys[0 : 4])
        state_matrix = xor_of_matrix(state_matrix, round_key)

        for i in range(self.rounds):
            state_matrix = byte_substitution_matrix(state_matrix)
            for j in range(1, 4):
                state_matrix[j] = cyclic_left_shift_vector(state_matrix[j], j)

            if i != self.rounds - 1:
                state_matrix = mix_columns(state_matrix)

            round_key = construct_state_matrix(self.keys[4 * (i + 1) : 4 * (i + 2)])
            state_matrix = xor_of_matrix(state_matrix, round_key)

        return state_matrix_to_bytes(state_matrix)

    # private method to decrypt a block of 128-bit
    def __decrypt_block(self, cipher_text: str | bytes) -> bytes:
        if len(cipher_text) != BLOCK_SIZE_BYTES:
            raise ValueError("Invalid Ciphertext")

        state_matrix = construct_state_matrix(cipher_text)

        round_key = construct_state_matrix(self.keys[self.rounds * 4 : self.rounds * 4 + 4])
        state_matrix = xor_of_matrix(state_matrix, round_key)

        for i in range(self.rounds - 1, -1, -1):
            for j in range(1, 4):
                state_matrix[j] = cyclic_right_shift_vector(state_matrix[j], j)

            state_matrix = inverse_byte_substitution_matrix(state_matrix)

            round_key = construct_state_matrix(self.keys[4 * i : 4 * (i + 1)])
            state_matrix = xor_of_matrix(state_matrix, round_key)
            
            if i != 0:
                state_matrix = inverse_mix_columns(state_matrix)

        return state_matrix_to_bytes(state_matrix)

    # private method to encrypt data (multiple of 128-bit) using ECB mode (with threads)
    def __encrypt_ECB(self, plain_text: str | bytes) -> bytes:
        if len(plain_text) % BLOCK_SIZE_BYTES:
            raise ValueError("Plaintext in not padded properly")
        
        blocks = []
        for i in range(len(plain_text) // BLOCK_SIZE_BYTES):
            blocks.append(plain_text[i * BLOCK_SIZE_BYTES : (i + 1) * BLOCK_SIZE_BYTES])

        threads = []
        executor = ThreadPoolExecutor()
        for block in blocks:
            threads.append(executor.submit(self.__encrypt_block, block))

        encrypted_blocks = []
        for thread in threads:
            encrypted_blocks.append(thread.result())

        cipher_text = bytes()
        for enc in encrypted_blocks:
            cipher_text += enc

        return cipher_text

    # private method to decrypt data (multiple of 128-bit) using ECB mode (with threads)
    def __decrypt_ECB(self, cipher_text: str | bytes) -> bytes:        
        if len(cipher_text) % BLOCK_SIZE_BYTES:
            raise ValueError("Invalid Ciphertext")
        
        blocks = []
        for i in range(len(cipher_text) // BLOCK_SIZE_BYTES):
            blocks.append(cipher_text[i * BLOCK_SIZE_BYTES : (i + 1) * BLOCK_SIZE_BYTES])

        threads = []
        executor = ThreadPoolExecutor()
        for block in blocks:
            threads.append(executor.submit(self.__decrypt_block, block))

        decrypted_blocks = []
        for thread in threads:
            decrypted_blocks.append(thread.result())

        plain_text = bytes()
        for dec in decrypted_blocks:
            plain_text += dec

        return plain_text

    # private method to encrypt data (multiple of 128-bit) using CBC mode
    def __encrypt_CBC(self, plain_text: str | bytes, IV: str | bytes) -> bytes:
        """Receives plain_text and IV
        
        returns IV and ciphertext in bytes form e.g., return IV, ciphertext
        """
        if len(plain_text) % BLOCK_SIZE_BYTES:
            raise ValueError("Plaintext in not padded properly")

        blocks = []
        for i in range(len(plain_text) // BLOCK_SIZE_BYTES):
            blocks.append(plain_text[i * BLOCK_SIZE_BYTES : (i + 1) * BLOCK_SIZE_BYTES])
        state = IV
        encrypted_blocks = []
        for block in blocks:
            input = state_matrix_to_bytes(xor_of_matrix(construct_state_matrix(state), construct_state_matrix(block)))         
            state = self.__encrypt_block(input)
            encrypted_blocks.append(state)

        cipher_text = bytes()
        for enc in encrypted_blocks:
            cipher_text += enc

        return IV, cipher_text

    # private method to decrypt data (multiple of 128-bit) using CBC mode
    def __decrypt_CBC(self, cipher_text: str | bytes, IV: str | bytes) -> bytes:
        if isinstance(cipher_text, str):
            cipher_text = string_to_bytes(cipher_text)

        if isinstance(IV, str):
            IV = string_to_bytes(IV)

        if len(IV) != BLOCK_SIZE_BYTES:
            raise ValueError("Invalid IV")

        if len(cipher_text) % BLOCK_SIZE_BYTES:
            raise ValueError("Invalid Ciphertext")

        blocks = []
        for i in range(len(cipher_text) // BLOCK_SIZE_BYTES):
            blocks.append(cipher_text[i * BLOCK_SIZE_BYTES : (i + 1) * BLOCK_SIZE_BYTES])

        state = IV
        decrypted_blocks = []
        for block in blocks:
            input = self.__decrypt_block(block)
            decrypted_block = state_matrix_to_bytes(xor_of_matrix(construct_state_matrix(state), construct_state_matrix(input)))
            decrypted_blocks.append(decrypted_block)
            state = block

        plain_text = bytes()
        for dec in decrypted_blocks:
            plain_text += dec

        return plain_text

    # public method to encrypt data using mode specified in constructor
    def encrypt(self, plain_text: str | bytes, IV: str | bytes | None = None) -> bytes:
        """Receives plain_text and IV (can be none incase of ECB)

        It pads data automatically
        Incase of CBC:
        It returns IV and ciphertext in bytes form e.g., return IV, ciphertext
        Incase of ECB:
        It returns ciphertext in bytes form e.g., return ciphertext
        """
        if isinstance(plain_text, str):
            plain_text = string_to_bytes(plain_text)
        plain_text = pad(plain_text)

        if self.mode == AES.ECB:
            return self.__encrypt_ECB(plain_text)
        elif self.mode == AES.CBC:
            if IV is None or IV == '' or IV == b'':
                IV = token_bytes(BLOCK_SIZE_BYTES)
            elif isinstance(IV, str):
                IV = string_to_bytes(IV)

            if len(IV) != BLOCK_SIZE_BYTES:
                raise ValueError("Invalid IV")
            return self.__encrypt_CBC(plain_text, IV)
        else:
            return bytes()

    # public method to decrypt data using mode specified in constructor
    def decrypt(self, cipher_text: str | bytes, IV: str | bytes) -> bytes:
        """Receives cipher_text and IV (can be none incase of ECB)

        It return unpadded data
        Incase of CBC:
        It returns plaintext in bytes form e.g., return plaintext
        Incase of ECB:
        It returns plaintext in bytes form e.g., return plaintext
        """
        if len(cipher_text) % BLOCK_SIZE_BYTES:
            raise ValueError("Invalid Ciphertext")

        if self.mode == AES.ECB:
            return unpad(self.__decrypt_ECB(cipher_text))
        elif self.mode == AES.CBC:
            if len(IV) != BLOCK_SIZE_BYTES:
                raise ValueError("Invalid IV")
            return unpad(self.__decrypt_CBC(cipher_text, IV))
        else:
            return bytes()


# key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
# key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
#         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
# key = "".join(chr(i) for i in key)

# plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xee]
# plaintext = "".join(chr(i) for i in plaintext)

# IV = [00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
# IV = "".join(chr(i) for i in IV)

# key = "12312312312312312312312312312312"
# plaintext = "12312312312312311231564654564656465465456465465456456465465"

# aes = AES(key, AES.CBC)
# IV, cipher = aes.encrypt(plaintext)
# print(cipher)
# print(IV)
# plain = aes.decrypt(cipher, IV)
# print(plain)

# state_matrix = construct_state_matrix(plain)
# state_matrix_in_hex = [[hex(val) for val in row] for row in state_matrix]
# print(state_matrix_in_hex)

# parsing arguments

description = """
Description:
    ‣ This is a standalone AES Cipher (with no dependencies)
    ‣ Stores ciphertext in file to avoid loss of bits
    ‣ Currently only ECB and CBC modes are in working condition
    ‣ IV is required for decryption in CBC mode for text
"""

parser = argparse.ArgumentParser(description=description, usage='aes.py [options]')
parser.add_argument('-k', '--key', help='for specifying key -- either contains 16 characters, 24 characters or 32 characters', required=True)
parser.add_argument('-m', '--mode', choices=('ECB', 'CBC'), help='for specifying encryption/decryption mode (uses ECB by default)', default='ECB')
parser.add_argument('-iv', help='for specifying 16 bytes Initialization Vector required for CBC mode (if not provided random 16 bytes will be generated)')
parser.add_argument('-o', '--operation', help='for performing encrytion', choices=('encrypt', 'decrypt'), required=True)
parser.add_argument('-t', '--text', help='for specifying text')
parser.add_argument('-f', '--file', help='for specifying file')
parser = parser.parse_args()

if len(parser.key) != AES256[KEY_SIZE] // BYTE and len(parser.key) != AES192[KEY_SIZE] // BYTE and len(parser.key) != AES128[KEY_SIZE] // BYTE:
    raise ValueError('Invalid Key')

if (parser.file == None and parser.text == None) or (parser.file != None and parser.text != None):
    raise ValueError('Please specify either a file or text to encrypt/decrypt')

if parser.mode != None and parser.mode == "CBC" and parser.operation == "decrypt" and parser.text != None and len(parser.iv) != BLOCK_SIZE_BYTES:
    raise ValueError('Invalid IV')

aes = AES(parser.key, parser.mode)
if parser.operation == 'encrypt' and parser.file:
    if not exists(parser.file):
        raise ValueError(f"{parser.file} doesn't exists")
    with open(parser.file, 'rb') as f:
        pt = f.read()
    
    if parser.mode == AES.ECB:
        ct = aes.encrypt(pt)
        with open(parser.file + '.enc', 'wb') as f:
            f.write(ct)
    elif parser.mode == AES.CBC:
        iv, ct = aes.encrypt(pt, parser.iv)
        with open(parser.file + '.enc', 'wb') as f:
            f.write(iv)
            f.write(ct)

elif parser.operation == 'decrypt' and parser.file:
    if not exists(parser.file):
        raise ValueError(f"{parser.file} doesn't exists")
    if '.enc' not in parser.file:
        raise ValueError(f"{parser.file} is not encrypted")

    iv = None
    with open(parser.file, 'rb') as f:
        if parser.mode == 'CBC':
            iv = f.read(BLOCK_SIZE_BYTES)
        ct = f.read()
    
    pt = aes.decrypt(ct, iv)
    with open(parser.file[:-4], 'wb') as f:
        f.write(pt)        

elif parser.operation == 'encrypt' and parser.text:   
    file_name = input('Please enter file_name to store ciphertext: ')

    if parser.mode == AES.ECB:
        ct = aes.encrypt(parser.text)
        
        print('Key:', parser.key)
        print('Ciphertext:', bytes_to_string(ct))

        with open(file_name, 'wb') as f:
            f.write(ct)

    elif parser.mode == AES.CBC:
        iv, ct = aes.encrypt(parser.text, parser.iv)
        
        print('Key:', parser.key)
        print('IV:', iv)
        print('Ciphertext:', bytes_to_string(ct))
    
        with open(file_name, 'wb') as f:
            f.write(iv)
            f.write(ct)

elif parser.operation == 'decrypt' and parser.text:
    if not exists(parser.text):
        raise ValueError(f"{parser.text} doesn't exists")

    iv = None
    with open(parser.text, 'rb') as f:
        if parser.mode == 'CBC':
            iv = f.read(BLOCK_SIZE_BYTES)
        ct = f.read()
    
    pt = aes.decrypt(ct, iv)
    # pt = aes.decrypt(parser.text, parser.iv)
        
    print('Key:', parser.key)
    print('Plaintext:', bytes_to_string(pt))

