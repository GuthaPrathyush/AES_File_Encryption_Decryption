import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = hashlib.sha256(b"your-secret-key").digest()

def encrypt_text_file(input_file, output_file):
    cipher = AES.new(KEY, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_file, "r") as f:
        plaintext = f.read().encode()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, "wb") as f:
        f.write(iv + ciphertext)

    print("Text file encrypted successfully.")


def decrypt_text_file(input_file, output_file):
    with open(input_file, "rb") as f:
        iv = f.read(16)  # First 16 bytes are IV
        ciphertext = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, "w") as f:
        f.write(plaintext.decode())

    print("Text file decrypted successfully.")


# Example usage
if __name__ == "__main__":
    encrypt_text_file("sample.txt", "encrypted.txt")
    decrypt_text_file("encrypted.txt", "decrypted.txt")

