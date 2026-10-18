# gui/app.py
import tkinter as tk
from tkinter import messagebox
import sys
import os

# 确保能找到 saes 包
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from saes.core import s_aes_encrypt, s_aes_decrypt


class SAESGui:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES 加解密工具 (第1关 & 第3关)")
        self.root.geometry("600x450")

        # 1. 密钥输入
        tk.Label(root, text="密钥 (16-bit 十六进制，如 4AF5):", font=("Arial", 10)).pack(pady=(10, 0))
        self.entry_key = tk.Entry(root, width=50)
        self.entry_key.insert(0, "4AF5")
        self.entry_key.pack(pady=5)

        # 2. 输入数据 (明文或密文)
        tk.Label(root, text="输入数据 (16-bit 十六进制 如 D728，或 ASCII 字符串):", font=("Arial", 10)).pack(
            pady=(10, 0))
        self.text_input = tk.Text(root, height=4, width=60)
        self.text_input.insert("1.0", "D728")  # 默认填入标准测试向量
        self.text_input.pack(pady=5)

        # 3. 按钮区域
        frame_btns = tk.Frame(root)
        frame_btns.pack(pady=10)

        btn_encrypt = tk.Button(frame_btns, text="加密 (Encrypt)", command=self.do_encrypt, bg="#a3c4f3", width=15)
        btn_encrypt.pack(side=tk.LEFT, padx=10)

        btn_decrypt = tk.Button(frame_btns, text="解密 (Decrypt)", command=self.do_decrypt, bg="#f3a3a3", width=15)
        btn_decrypt.pack(side=tk.LEFT, padx=10)

        # 4. 输出结果
        tk.Label(root, text="输出结果:", font=("Arial", 10)).pack(pady=(10, 0))
        self.text_output = tk.Text(root, height=6, width=60, bg="#f0f0f0")
        self.text_output.pack(pady=5)

    def get_key(self):
        try:
            key_hex = self.entry_key.get().strip()
            key = int(key_hex, 16)
            if key < 0 or key > 0xFFFF:
                raise ValueError
            return key
        except ValueError:
            messagebox.showerror("错误", "密钥必须是 16-bit 的十六进制数 (如 4AF5)！")
            return None

    def do_encrypt(self):
        key = self.get_key()
        if key is None: return

        input_str = self.text_input.get("1.0", tk.END).strip()
        if not input_str: return

        self.text_output.delete("1.0", tk.END)

        # 简单判断：如果输入像十六进制且长度为4，走16-bit加密（第1关）
        try:
            if len(input_str) == 4:
                plaintext = int(input_str, 16)
                ciphertext = s_aes_encrypt(plaintext, key)
                self.text_output.insert(tk.END, f"十六进制密文: {ciphertext:04X}\n二进制密文: {ciphertext:016b}")
            else:
                raise ValueError
        except ValueError:
            # 否则走 ASCII 字符串加密（第3关）
            self.text_output.insert(tk.END, "【ASCII 字符串加密模式】\n")
            # 补全为偶数长度（2字节一组）
            if len(input_str) % 2 != 0:
                input_str += "\x00"

            result_hex = []
            for i in range(0, len(input_str), 2):
                block_str = input_str[i:i + 2]
                # 转为 16-bit 整数
                block = (ord(block_str[0]) << 8) | ord(block_str[1])
                enc_block = s_aes_encrypt(block, key)
                result_hex.append(f"{enc_block:04X}")

            self.text_output.insert(tk.END, " ".join(result_hex))

    def do_decrypt(self):
        key = self.get_key()
        if key is None: return

        input_str = self.text_input.get("1.0", tk.END).strip()
        if not input_str: return

        self.text_output.delete("1.0", tk.END)

        # 如果是一串以空格分隔的十六进制块（ASCII 密文）
        if " " in input_str or len(input_str) > 4:
            try:
                blocks = input_str.split()
                result_str = ""
                for b in blocks:
                    c = int(b, 16)
                    p = s_aes_decrypt(c, key)
                    # 还原为字符
                    result_str += chr((p >> 8) & 0xFF) + chr(p & 0xFF)
                # 去掉补齐的空字符
                result_str = result_str.replace('\x00', '')
                self.text_output.insert(tk.END, f"ASCII 解密结果:\n{result_str}")
            except Exception as e:
                messagebox.showerror("错误", f"密文格式不正确！\n{str(e)}")
        else:
            # 16-bit 单块解密
            try:
                ciphertext = int(input_str, 16)
                plaintext = s_aes_decrypt(ciphertext, key)
                self.text_output.insert(tk.END, f"十六进制明文: {plaintext:04X}\n二进制明文: {plaintext:016b}")
            except ValueError:
                messagebox.showerror("错误", "密文必须是 16-bit 的十六进制数！")


if __name__ == "__main__":
    root = tk.Tk()
    app = SAESGui(root)
    root.mainloop()