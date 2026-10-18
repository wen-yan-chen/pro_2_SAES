# gui/app.py
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from saes.core import s_aes_encrypt, s_aes_decrypt
from saes.multi_crypto import double_encrypt, double_decrypt, meet_in_the_middle_attack, triple_encrypt, triple_decrypt
from saes.cbc_mode import cbc_encrypt, cbc_decrypt


class SAESGui:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES 综合加解密工具 (全关卡)")
        self.root.geometry("700x600")

        # 创建选项卡
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.tab_basic = ttk.Frame(self.notebook)
        self.tab_multi = ttk.Frame(self.notebook)
        self.tab_cbc = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_basic, text='第1/3关: 基础加解密')
        self.notebook.add(self.tab_multi, text='第4关: 多重加密')
        self.notebook.add(self.tab_cbc, text='第5关: CBC工作模式')

        self.setup_basic_tab()
        self.setup_multi_tab()
        self.setup_cbc_tab()

    def setup_basic_tab(self):
        # 基础选项卡
        frame = tk.Frame(self.tab_basic)
        frame.pack(pady=20)

        tk.Label(frame, text="密钥 (16-bit, 如 4AF5):").grid(row=0, column=0, pady=5)
        self.basic_key = tk.Entry(frame, width=30)
        self.basic_key.insert(0, "4AF5")
        self.basic_key.grid(row=0, column=1, pady=5)

        tk.Label(frame, text="输入数据 (16进制或ASCII):").grid(row=1, column=0, pady=5)
        self.basic_input = tk.Text(frame, height=4, width=40)
        self.basic_input.insert("1.0", "D728")
        self.basic_input.grid(row=1, column=1, pady=5)

        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        tk.Button(btn_frame, text="单次加密", command=self.do_basic_encrypt).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="单次解密", command=self.do_basic_decrypt).pack(side=tk.LEFT, padx=10)

        self.basic_output = tk.Text(frame, height=6, width=50, bg="#f0f0f0")
        self.basic_output.grid(row=3, column=0, columnspan=2, pady=5)

    def setup_multi_tab(self):
        # 多重加密选项卡
        frame = tk.Frame(self.tab_multi)
        frame.pack(pady=20)

        tk.Label(frame, text="32-bit / 48-bit 密钥 (16进制):").grid(row=0, column=0, pady=5)
        self.multi_key = tk.Entry(frame, width=30)
        self.multi_key.insert(0, "4AF51234")  # 默认32bit
        self.multi_key.grid(row=0, column=1, pady=5)

        tk.Label(frame, text="输入数据 (16-bit 16进制):").grid(row=1, column=0, pady=5)
        self.multi_input = tk.Entry(frame, width=35)
        self.multi_input.insert(0, "D728")
        self.multi_input.grid(row=1, column=1, pady=5)

        btn_frame1 = tk.Frame(frame)
        btn_frame1.grid(row=2, column=0, columnspan=2, pady=5)
        tk.Button(btn_frame1, text="双重加密", command=lambda: self.do_multi(True, False)).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame1, text="双重解密", command=lambda: self.do_multi(False, False)).pack(side=tk.LEFT, padx=10)

        btn_frame2 = tk.Frame(frame)
        btn_frame2.grid(row=3, column=0, columnspan=2, pady=5)
        tk.Button(btn_frame2, text="三重加密(48-bit)", command=lambda: self.do_multi(True, True)).pack(side=tk.LEFT,
                                                                                                       padx=10)
        tk.Button(btn_frame2, text="三重解密(48-bit)", command=lambda: self.do_multi(False, True)).pack(side=tk.LEFT,
                                                                                                        padx=10)

        tk.Button(frame, text="运行中间相遇攻击 (可能耗时几秒)", bg="orange", command=self.do_mitm).grid(row=4,
                                                                                                         column=0,
                                                                                                         columnspan=2,
                                                                                                         pady=10)

        self.multi_output = tk.Text(frame, height=8, width=60, bg="#f0f0f0")
        self.multi_output.grid(row=5, column=0, columnspan=2, pady=5)

    def setup_cbc_tab(self):
        # CBC 选项卡
        frame = tk.Frame(self.tab_cbc)
        frame.pack(pady=20)

        tk.Label(frame, text="16-bit 密钥:").grid(row=0, column=0, pady=5)
        self.cbc_key = tk.Entry(frame, width=20)
        self.cbc_key.insert(0, "4AF5")
        self.cbc_key.grid(row=0, column=1, pady=5)

        tk.Label(frame, text="16-bit IV (初始向量):").grid(row=0, column=2, pady=5)
        self.cbc_iv = tk.Entry(frame, width=20)
        self.cbc_iv.insert(0, "0000")
        self.cbc_iv.grid(row=0, column=3, pady=5)

        tk.Label(frame, text="CBC 输入明文/密文 (支持长字符串或空格分隔的16进制):").grid(row=1, column=0, columnspan=4,
                                                                                         pady=5)
        self.cbc_input = tk.Text(frame, height=4, width=60)
        self.cbc_input.insert("1.0", "HELLO CBC MODE")
        self.cbc_input.grid(row=2, column=0, columnspan=4, pady=5)

        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=4, pady=10)
        tk.Button(btn_frame, text="CBC 加密", command=self.do_cbc_encrypt).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="CBC 解密", command=self.do_cbc_decrypt).pack(side=tk.LEFT, padx=10)

        self.cbc_output = tk.Text(frame, height=6, width=60, bg="#f0f0f0")
        self.cbc_output.grid(row=4, column=0, columnspan=4, pady=5)

    # --- 逻辑处理函数 ---
    def do_basic_encrypt(self):
        try:
            key = int(self.basic_key.get(), 16)
            data = self.basic_input.get("1.0", "end-1c").strip()
            if len(data) == 4:
                res = s_aes_encrypt(int(data, 16), key)
                self.basic_output.delete("1.0", tk.END)
                self.basic_output.insert(tk.END, f"密文: {res:04X}")
            else:
                if len(data) % 2 != 0: data += "\x00"
                res = [f"{s_aes_encrypt((ord(data[i]) << 8) | ord(data[i + 1]), key):04X}" for i in
                       range(0, len(data), 2)]
                self.basic_output.delete("1.0", tk.END)
                self.basic_output.insert(tk.END, " ".join(res))
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_basic_decrypt(self):
        try:
            key = int(self.basic_key.get(), 16)
            data = self.basic_input.get("1.0", "end-1c").strip()
            if " " in data:
                res_str = ""
                for block in data.split():
                    p = s_aes_decrypt(int(block, 16), key)
                    res_str += chr((p >> 8) & 0xFF) + chr(p & 0xFF)
                self.basic_output.delete("1.0", tk.END)
                self.basic_output.insert(tk.END, res_str.replace('\x00', ''))
            else:
                res = s_aes_decrypt(int(data, 16), key)
                self.basic_output.delete("1.0", tk.END)
                self.basic_output.insert(tk.END, f"明文: {res:04X}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_multi(self, is_encrypt, is_triple):
        try:
            key_str = self.multi_key.get()
            key = int(key_str, 16)
            plain_or_cipher = int(self.multi_input.get(), 16)

            if is_triple:
                if len(key_str) != 12: raise ValueError("三重加密需要 48-bit 密钥 (12个16进制字符)")
                res = triple_encrypt(plain_or_cipher, key) if is_encrypt else triple_decrypt(plain_or_cipher, key)
            else:
                if len(key_str) != 8: raise ValueError("双重加密需要 32-bit 密钥 (8个16进制字符)")
                res = double_encrypt(plain_or_cipher, key) if is_encrypt else double_decrypt(plain_or_cipher, key)

            self.multi_output.delete("1.0", tk.END)
            self.multi_output.insert(tk.END, f"结果: {res:04X}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_mitm(self):
        try:
            self.multi_output.delete("1.0", tk.END)
            self.multi_output.insert(tk.END, "正在计算，请稍候...\n")
            self.root.update()

            p = int(self.multi_input.get(), 16)
            # 这里假设用户想要用当前的密文去碰撞，为了演示，我们现生成一个密文
            # 真实攻击中，这是已知的明密文对
            key32 = int(self.multi_key.get(), 16)
            c = double_encrypt(p, key32)

            start_time = time.time()
            keys = meet_in_the_middle_attack(p, c)
            elapsed = time.time() - start_time

            out = f"已知明密文对: P={p:04X}, C={c:04X}\n"
            out += f"耗时: {elapsed:.2f} 秒\n"
            out += f"找到 {len(keys)} 个可能的密钥对:\n"
            for k1, k2 in keys[:5]:  # 只展示前5个防刷屏
                out += f"K1={k1:04X}, K2={k2:04X}\n"
            if len(keys) > 5: out += "...\n"

            self.multi_output.delete("1.0", tk.END)
            self.multi_output.insert(tk.END, out)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_cbc_encrypt(self):
        try:
            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            text = self.cbc_input.get("1.0", "end-1c").strip().encode('utf-8')
            blocks = cbc_encrypt(text, key, iv)
            res_hex = " ".join([f"{b:04X}" for b in blocks])
            self.cbc_output.delete("1.0", tk.END)
            self.cbc_output.insert(tk.END, res_hex)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_cbc_decrypt(self):
        try:
            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            text = self.cbc_input.get("1.0", "end-1c").strip()
            blocks = [int(b, 16) for b in text.split()]
            plain_bytes = cbc_decrypt(blocks, key, iv)
            # 使用 latin-1 解码防止乱码报错
            res_str = plain_bytes.decode('utf-8', errors='replace').replace('\x00', '')
            self.cbc_output.delete("1.0", tk.END)
            self.cbc_output.insert(tk.END, f"解密结果:\n{res_str}")
        except Exception as e:
            messagebox.showerror("错误", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SAESGui(root)
    root.mainloop()