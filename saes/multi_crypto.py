# saes/multi_crypto.py
from .core import s_aes_encrypt, s_aes_decrypt


def double_encrypt(plaintext, key32):
    """双重加密: C = Enc(K2, Enc(K1, P))"""
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    return s_aes_encrypt(s_aes_encrypt(plaintext, k1), k2)


def double_decrypt(ciphertext, key32):
    """双重解密: P = Dec(K1, Dec(K2, C))"""
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    return s_aes_decrypt(s_aes_decrypt(ciphertext, k2), k1)


def meet_in_the_middle_attack(plaintext, ciphertext):
    """中间相遇攻击 (针对双重加密)"""
    # 1. 遍历所有可能的 K1，计算中间值并存入字典
    mid_dict = {}
    for k1 in range(0x10000):
        mid_val = s_aes_encrypt(plaintext, k1)
        mid_dict[mid_val] = k1

    # 2. 遍历所有可能的 K2，反向解密寻找匹配
    found_keys = []
    for k2 in range(0x10000):
        mid_val = s_aes_decrypt(ciphertext, k2)
        if mid_val in mid_dict:
            k1 = mid_dict[mid_val]
            found_keys.append((k1, k2))

    return found_keys


def triple_encrypt(plaintext, key48):
    """三重加密 (选择 48-bit 密钥模式 K1+K2+K3)"""
    k1 = (key48 >> 32) & 0xFFFF
    k2 = (key48 >> 16) & 0xFFFF
    k3 = key48 & 0xFFFF
    # 加密: C = Enc(K3, Dec(K2, Enc(K1, P)))
    return s_aes_encrypt(s_aes_decrypt(s_aes_encrypt(plaintext, k1), k2), k3)


def triple_decrypt(ciphertext, key48):
    """三重解密"""
    k1 = (key48 >> 32) & 0xFFFF
    k2 = (key48 >> 16) & 0xFFFF
    k3 = key48 & 0xFFFF
    # 解密: P = Dec(K1, Enc(K2, Dec(K3, C)))
    return s_aes_decrypt(s_aes_encrypt(s_aes_decrypt(ciphertext, k3), k2), k1)