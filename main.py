import os
import hashlib
import binascii
from pbkdf2 import PBKDF2

# Bước 1: Tạo entropy (128 bit cho 12 từ)
entropy = os.urandom(16)  # 16 bytes = 128 bit

# Bước 2: Tính toán checksum
entropy_bits = bin(int.from_bytes(entropy, byteorder='big'))[2:].zfill(128)
checksum = bin(int(hashlib.sha256(entropy).hexdigest(), 16))[2:].zfill(256)[:4]
entropy_with_checksum = entropy_bits + checksum

# Bước 3: Chia thành các phần 11 bit
words_indices = [int(entropy_with_checksum[i:i+11], 2) for i in range(0, len(entropy_with_checksum), 11)]

# Bước 4: Ánh xạ số với danh sách từ (BIP-39 word list)
with open('bip39_wordlist.txt', 'r') as file:
    wordlist = file.read().splitlines()

mnemonic = ' '.join([wordlist[index] for index in words_indices])

# Bước 5: Hiển thị cụm từ phục hồi
print("Mnemonic Phrase:", mnemonic)

# Bước 6: Sử dụng cụm từ phục hồi để tạo khóa cá nhân (private key)
passphrase = ''  # Bạn có thể thêm passphrase tùy chọn ở đây
seed = PBKDF2(mnemonic, 'mnemonic' + passphrase, iterations=2048, macmodule=hmac, digestmodule=hashlib.sha512).read(64)

print("Seed:", binascii.hexlify(seed).decode())
