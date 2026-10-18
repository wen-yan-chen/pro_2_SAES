# tests/test_core.py
import os
import sys

# 允许直接从仓库根目录执行 python tests/test_core.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from saes.core import s_aes_encrypt, s_aes_decrypt


def test_saes():
    # 教科书附录 D 标准测试向量
    plaintext = 0xD728  # 1101 0111 0010 1000
    key = 0x4AF5  # 0100 1010 1111 0101
    expected_ciphertext = 0x24EC  # 0010 0100 1110 1100

    # 测试加密
    ciphertext = s_aes_encrypt(plaintext, key)
    print(f"明文: {hex(plaintext)}, 密钥: {hex(key)}")
    print(f"预期密文: {hex(expected_ciphertext)}, 实际密文: {hex(ciphertext)}")
    assert ciphertext == expected_ciphertext, "加密失败，结果不匹配！"

    # 测试解密
    decrypted = s_aes_decrypt(ciphertext, key)
    print(f"解密结果: {hex(decrypted)}")
    assert decrypted == plaintext, "解密失败，无法还原明文！"

    print("✅ 测试通过！核心算法完全正确！")


if __name__ == "__main__":
    test_saes()