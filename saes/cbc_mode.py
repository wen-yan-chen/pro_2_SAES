# saes/cbc_mode.py
from .core import s_aes_encrypt, s_aes_decrypt


def cbc_encrypt(plaintext_bytes, key16, iv16):
    # 简单补齐偶数长度（2字节对齐）
    if len(plaintext_bytes) % 2 != 0:
        plaintext_bytes += b'\x00'

    ciphertext_blocks = []
    prev_cipher = iv16

    for i in range(0, len(plaintext_bytes), 2):
        block = (plaintext_bytes[i] << 8) | plaintext_bytes[i + 1]
        # 异或前一个密文块（或初始向量）
        block_to_encrypt = block ^ prev_cipher
        encrypted = s_aes_encrypt(block_to_encrypt, key16)

        ciphertext_blocks.append(encrypted)
        prev_cipher = encrypted  # 更新前一个密文块

    return ciphertext_blocks


def cbc_decrypt(ciphertext_blocks, key16, iv16):
    plaintext_bytes = bytearray()
    prev_cipher = iv16

    for block in ciphertext_blocks:
        decrypted = s_aes_decrypt(block, key16)
        # 异或前一个密文块（或初始向量）
        original_block = decrypted ^ prev_cipher

        plaintext_bytes.append((original_block >> 8) & 0xFF)
        plaintext_bytes.append(original_block & 0xFF)
        prev_cipher = block  # 更新前一个密文块

    return bytes(plaintext_bytes)