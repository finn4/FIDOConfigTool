import struct
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from smartcard.System import readers

# --- 硬件协议常量 ---
AID_FIDO_MAN = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
AID_PICO_RESCUE = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21, 0x00]

TAG_VIDPID = 0x00
TAG_LED_BRIGHTNESS = 0x05
TAG_PRODUCT_NAME = 0x09
TAG_ENABLED_CURVES = 0x0A
TAG_TOUCH_CONF = 0x0D

INS_MGMT_READ = 0x1D
INS_RESCUE_WRITE_PHY = 0x1C
INS_RESCUE_SECURE = 0x1D
INS_RESCUE_READ_INFO = 0x1E


class PicoKeyManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Pico Key 配置工具 by finn4")
        self.root.geometry("800x600")

        self.setup_vars()
        self.setup_ui()
        self.refresh_readers()

    def setup_vars(self):
        self.use_vidpid = tk.BooleanVar(value=False)
        self.vidpid_preset = tk.StringVar(value="Yubikey 5 (1050:0407)")
        self.custom_vid = tk.StringVar(value="20A0")
        self.custom_pid = tk.StringVar(value="42B1")

        self.presets = {
            "Yubikey 5 (1050:0407)": (0x1050, 0x0407),
            "Nitrokey FIDO2 (20A0:42B1)": (0x20A0, 0x42B1),
            "Nitrokey HSM (20A0:4230)": (0x20A0, 0x4230),
            "Google Titan (18D1:5026)": (0x18D1, 0x5026),
            "自定义": None
        }

        self.use_name = tk.BooleanVar(value=False)
        self.name_val = tk.StringVar(value="YubiKey 5")
        self.use_bright = tk.BooleanVar(value=False)
        self.bright_val = tk.IntVar(value=1)
        self.use_touch = tk.BooleanVar(value=False)
        self.touch_enable = tk.BooleanVar(value=True)
        self.touch_threshold = tk.IntVar(value=50)
        self.use_curves = tk.BooleanVar(value=False)
        self.curve_p256 = tk.BooleanVar(value=True)
        self.curve_k1 = tk.BooleanVar(value=False)
        self.curve_ed = tk.BooleanVar(value=False)

    def setup_ui(self):
        # 1. 读卡器连接
        conn_frame = ttk.LabelFrame(self.root, text=" 1. 设备连接 ", padding=10)
        conn_frame.pack(fill="x", padx=10, pady=5)
        self.reader_combo = ttk.Combobox(conn_frame, state="readonly")
        self.reader_combo.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(conn_frame, text="刷新", command=self.refresh_readers).pack(side="left")
        ttk.Button(conn_frame, text="识别设备", command=self.detect_device).pack(side="left", padx=5)

        # 2. 信息显示
        self.status_box = tk.Text(self.root, height=4, bg="#f8f9fa", padx=10, pady=5, state="disabled",
                                  font=("Consolas", 9))
        self.status_box.pack(fill="x", padx=10, pady=5)

        # 3. 配置面板
        cfg_frame = ttk.LabelFrame(self.root, text=" 2. 硬件配置 (勾选后生效) ", padding=10)
        cfg_frame.pack(fill="both", padx=10, pady=5)

        # --- VID/PID 行 (优化自定义填写) ---
        f1 = ttk.Frame(cfg_frame)
        f1.pack(fill="x", pady=4)
        ttk.Checkbutton(f1, variable=self.use_vidpid).pack(side="left")
        ttk.Label(f1, text="USB VID:PID:", width=12).pack(side="left")

        self.combo_vp = ttk.Combobox(f1, textvariable=self.vidpid_preset, values=list(self.presets.keys()),
                                     state="readonly", width=25)
        self.combo_vp.pack(side="left", padx=5)
        self.combo_vp.bind("<<ComboboxSelected>>", self.toggle_custom_fields)

        # 自定义输入小框架 (初始隐藏或禁用)
        self.custom_vp_frame = ttk.Frame(f1)
        self.custom_vp_frame.pack(side="left", fill="x")
        ttk.Label(self.custom_vp_frame, text="V:").pack(side="left")
        self.ent_vid = ttk.Entry(self.custom_vp_frame, textvariable=self.custom_vid, width=6)
        self.ent_vid.pack(side="left", padx=2)
        ttk.Label(self.custom_vp_frame, text="P:").pack(side="left")
        self.ent_pid = ttk.Entry(self.custom_vp_frame, textvariable=self.custom_pid, width=6)
        self.ent_pid.pack(side="left", padx=2)

        self.toggle_custom_fields()  # 初始化状态

        # --- 名称 行 ---
        f2 = ttk.Frame(cfg_frame)
        f2.pack(fill="x", pady=4)
        ttk.Checkbutton(f2, variable=self.use_name).pack(side="left")
        ttk.Label(f2, text="产品名称:", width=12).pack(side="left")
        ttk.Entry(f2, textvariable=self.name_val).pack(side="left", fill="x", expand=True)

        # --- 触摸键 行 ---
        f_touch = ttk.Frame(cfg_frame)
        f_touch.pack(fill="x", pady=4)
        ttk.Checkbutton(f_touch, variable=self.use_touch).pack(side="left")
        ttk.Label(f_touch, text="触摸配置:", width=12).pack(side="left")
        ttk.Checkbutton(f_touch, text="启用", variable=self.touch_enable).pack(side="left")
        ttk.Label(f_touch, text=" 灵敏度:").pack(side="left")
        ttk.Scale(f_touch, from_=1, to=100, variable=self.touch_threshold).pack(side="left", fill="x", expand=True)
        ttk.Label(f_touch, textvariable=self.touch_threshold, width=3).pack(side="left")

        # --- 亮度 行 ---
        f3 = ttk.Frame(cfg_frame)
        f3.pack(fill="x", pady=4)
        ttk.Checkbutton(f3, variable=self.use_bright).pack(side="left")
        ttk.Label(f3, text="LED 亮度:", width=12).pack(side="left")
        ttk.Scale(f3, from_=0, to=255, variable=self.bright_val).pack(side="left", fill="x", expand=True)
        ttk.Label(f3, textvariable=self.bright_val, width=4).pack(side="left")

        # --- 曲线 行 ---
        f4 = ttk.Frame(cfg_frame)
        f4.pack(fill="x", pady=4)
        ttk.Checkbutton(f4, variable=self.use_curves).pack(side="left")
        ttk.Label(f4, text="算法曲线:", width=15).pack(side="left")
        ttk.Checkbutton(f4, text="P-256", variable=self.curve_p256).pack(side="left")
        ttk.Checkbutton(f4, text="secp256k1", variable=self.curve_k1).pack(side="left")
        ttk.Checkbutton(f4, text="Ed25519", variable=self.curve_ed).pack(side="left")

        ttk.Button(cfg_frame, text="🚀 写入选中的配置到硬件", command=self.apply_config).pack(pady=15)

        # 4. 底部栏
        bottom_tabs = ttk.Notebook(self.root)
        bottom_tabs.pack(fill="x", padx=10, pady=5)

        # Tab: 安全启动 (RP2350)
        tab_sec = ttk.Frame(bottom_tabs, padding=10)
        bottom_tabs.add(tab_sec, text="安全启动 (RP2350)")

        btn_check_secure = ttk.Button(tab_sec, text="🔍 查看硬件锁定状态", command=self.query_security)
        btn_check_secure.pack(pady=5, fill="x")

        # 使用红色警示背景的按钮 (使用标准 tk.Button 以便自定义颜色)
        btn_enable_secure = tk.Button(tab_sec, text="开启签名校验 (不可逆)",
                                      command=lambda: self.secure_action("ENABLE"),
                                      bg="#ffcccc", fg="#cc0000", font=("微软雅黑", 9, "bold"))
        btn_enable_secure.pack(pady=5, fill="x")

        btn_lock_hw = tk.Button(tab_sec, text="永久锁定硬件接口 (慎用)",
                                command=lambda: self.secure_action("LOCK"),
                                bg="#333333", fg="white", font=("微软雅黑", 9))
        btn_lock_hw.pack(pady=5, fill="x")

        # Tab: 重置
        tab_rst = ttk.Frame(bottom_tabs, padding=10)
        bottom_tabs.add(tab_rst, text="出厂重置")
        ttk.Label(tab_rst, text="确认(RESET):").pack(side="left", padx=5)
        self.reset_confirm = ttk.Entry(tab_rst, width=10);
        self.reset_confirm.pack(side="left", padx=5)
        tk.Button(tab_rst, text="执行重置", bg="#fee", fg="red", command=self.run_reset).pack(side="left", padx=10)

    def toggle_custom_fields(self, event=None):
        """根据下拉菜单决定是否启用自定义输入框"""
        if self.vidpid_preset.get() == "自定义":
            for child in self.custom_vp_frame.winfo_children():
                if isinstance(child, ttk.Entry): child.configure(state="normal")
        else:
            for child in self.custom_vp_frame.winfo_children():
                if isinstance(child, ttk.Entry): child.configure(state="disabled")

    def refresh_readers(self):
        try:
            self.readers = readers()
            self.reader_combo['values'] = [str(r) for r in self.readers]
            if self.readers: self.reader_combo.current(0)
        except:
            pass

    def send_apdu(self, conn, apdu):
        data, sw1, sw2 = conn.transmit(apdu)
        sw = (sw1 << 8) | sw2
        while (sw >> 8) == 0x61:
            res, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw & 0xFF])
            data += res
            sw = (sw1 << 8) | sw2
        return data, sw

    def detect_device(self):
        idx = self.reader_combo.current()
        if idx < 0: return
        conn = self.readers[idx].createConnection()
        try:
            conn.connect()
            info = []
            _, sw = self.send_apdu(conn, [0x00, 0xA4, 0x04, 0x04, len(AID_FIDO_MAN)] + AID_FIDO_MAN)
            if sw == 0x9000: info.append("✅ FIDO 应用就绪")
            # Rescue Info
            res_data, sw_res = self.send_apdu(conn, [0x00, 0xA4, 0x04, 0x04, len(AID_PICO_RESCUE)] + AID_PICO_RESCUE)
            if sw_res == 0x9000:
                p = {0: "RP2040", 1: "RP2350", 2: "ESP32"}.get(res_data[0], "未知")
                info.append(f"✅ 硬件平台: {p}")
            self.status_box.config(state="normal");
            self.status_box.delete("1.0", tk.END)
            self.status_box.insert(tk.END, "\n".join(info));
            self.status_box.config(state="disabled")
        except Exception as e:
            messagebox.showerror("通信失败", str(e))
        finally:
            conn.disconnect()

    def apply_config(self):
        payload = bytearray()
        summary = []

        if self.use_vidpid.get():
            p_name = self.vidpid_preset.get()
            if p_name == "自定义":
                try:
                    vid = int(self.custom_vid.get(), 16)
                    pid = int(self.custom_pid.get(), 16)
                    val = (vid, pid)
                except ValueError:
                    messagebox.showerror("格式错误", "VID/PID 必须是 16 进制数字 (例如 20A0)")
                    return
            else:
                val = self.presets[p_name]

            payload += bytes([TAG_VIDPID, 4]) + struct.pack(">HH", val[0], val[1])
            summary.append(f"- USB ID: {val[0]:04X}:{val[1]:04X}")

        if self.use_name.get():
            name_bytes = self.name_val.get().encode() + b'\x00'
            payload += bytes([TAG_PRODUCT_NAME, len(name_bytes)]) + name_bytes
            summary.append(f"- 产品名称: {self.name_val.get()}")

        if self.use_touch.get():
            en, th = (1 if self.touch_enable.get() else 0), self.touch_threshold.get()
            payload += bytes([TAG_TOUCH_CONF, 2, en, th])
            summary.append(f"- 触摸配置: {'开启' if en else '关闭'} (灵敏度: {th})")

        if self.use_bright.get():
            b = self.bright_val.get();
            payload += bytes([TAG_LED_BRIGHTNESS, 1, b])
            summary.append(f"- LED 亮度: {b}")

        if self.use_curves.get():
            mask = 0
            if self.curve_p256.get(): mask |= 0x01
            if self.curve_k1.get(): mask |= 0x08
            if self.curve_ed.get(): mask |= 0x80
            payload += bytes([TAG_ENABLED_CURVES, 4]) + struct.pack(">I", mask)
            summary.append(f"- 支持曲线掩码: {hex(mask)}")

        if not payload:
            messagebox.showwarning("提示", "请至少勾选一个要修改的项目")
            return

        if messagebox.askyesno("确认写入", "即将写入以下配置，是否继续？\n\n" + "\n".join(summary)):
            idx = self.reader_combo.current();
            conn = self.readers[idx].createConnection()
            try:
                conn.connect()
                self.send_apdu(conn, [0x00, 0xA4, 0x04, 0x04, len(AID_PICO_RESCUE)] + AID_PICO_RESCUE)
                apdu = [0x80, INS_RESCUE_WRITE_PHY, 0x01, 0x00, len(payload)] + list(payload)
                _, sw = self.send_apdu(conn, apdu)
                if sw == 0x9000:
                    messagebox.showinfo("成功", "写入成功！请重新插拔设备。")
                else:
                    messagebox.showerror("失败", f"错误码: {hex(sw)}")
            finally:
                conn.disconnect()

    def query_security(self):
        idx = self.reader_combo.current();
        conn = self.readers[idx].createConnection()
        try:
            conn.connect()
            self.send_apdu(conn, [0x00, 0xA4, 0x04, 0x04, len(AID_PICO_RESCUE)] + AID_PICO_RESCUE)
            data, sw = self.send_apdu(conn, [0x80, INS_RESCUE_READ_INFO, 0x03, 0x00, 0x00])
            if sw == 0x9000:
                msg = f"签名校验: {'开启' if data[0] else '关闭'}\n硬件锁定: {'已锁定' if data[1] else '未锁定'}"
                messagebox.showinfo("RP2350 安全状态", msg)
        finally:
            conn.disconnect()

    def secure_action(self, act):
        # 针对不同动作设置参数
        # P2=0x00: Enable Secure Boot (签名校验)
        # P2=0x01: Lock Debug/OTP (硬件永久锁定)
        p2 = 0x00 if act == "ENABLE" else 0x01
        action_name = "开启签名校验" if act == "ENABLE" else "永久锁定硬件接口"

        # 构造警告信息
        warning_msg = (
            f"确定要执行【{action_name}】吗？\n\n"
            "⚠️ 警告：此操作将向芯片熔丝（OTP）写入数据！\n"
            "1. 这是【不可逆】的操作，一旦执行无法撤销。\n"
            "2. 如果开启签名校验但未正确烧录密钥，设备将永久变砖。\n"
            "3. 如果锁定硬件，将永久禁用 SWD 调试接口。"
        )

        # 使用标准 messagebox 指令
        confirm = messagebox.askyesno("极端危险确认", warning_msg, icon='warning')

        if confirm:
            # 二次确认：要求输入特定字符串防止误点
            verify_str = simpledialog.askstring("最后核对", f"为了安全，请输入 '{act}' 以确认执行:")
            if verify_str == act:
                idx = self.reader_combo.current()
                if idx < 0: return
                conn = self.readers[idx].createConnection()
                try:
                    conn.connect()
                    # 1. 选择 Rescue Applet 模式
                    self.send_apdu(conn, [0x00, 0xA4, 0x04, 0x04, len(AID_PICO_RESCUE)] + AID_PICO_RESCUE)

                    # 2. 发送安全指令 (CLA=0x80, INS=0x1D, P1=0x00, P2=动作, Le=0)
                    # 指令格式依据 Pico Key 固件规范
                    apdu = [0x80, INS_RESCUE_SECURE, 0x00, p2, 0x00]
                    data, sw = self.send_apdu(conn, apdu)

                    if sw == 0x9000:
                        messagebox.showinfo("成功", f"【{action_name}】指令已成功执行！\n请重新插拔设备以使硬件熔丝生效。")
                    else:
                        messagebox.showerror("硬件拒绝",
                                             f"执行失败 (错误码: {hex(sw)})\n可能原因：操作已被执行过，或处于保护模式。")
                except Exception as e:
                    messagebox.showerror("通信错误", f"无法连接读卡器: {str(e)}")
                finally:
                    conn.disconnect()
            else:
                messagebox.showinfo("取消", "输入不匹配，操作已中止。")

    def run_reset(self):
        if self.reset_confirm.get() != "RESET": return
        idx = self.reader_combo.current();
        conn = self.readers[idx].createConnection()
        try:
            conn.connect()
            self.send_apdu(conn, [0x00, 0xA4, 0x04, 0x04, len(AID_FIDO_MAN)] + AID_FIDO_MAN)
            _, sw = self.send_apdu(conn, [0x00, 0x1E, 0x00, 0x00])
            if sw == 0x9000:
                messagebox.showinfo("指令发送", "请在 LED 闪烁时按下物理按键确认重置。")
            else:
                messagebox.showerror("重置失败", "设备拒绝了请求 (可能已超过上电 10 秒限制)")
        finally:
            conn.disconnect()


if __name__ == "__main__":
    root = tk.Tk()
    app = PicoKeyManager(root)
    root.mainloop()
