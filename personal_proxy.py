"""
Personal Proxy - واجهة بسيطة لإدارة Xray-core و SSH tunnel على ويندوز
المتطلبات:
  1) Python 3.9+  (tkinter مضمّنة)
  2) ملف xray.exe بجانب هذا البرنامج (من https://github.com/XTLS/Xray-core/releases)
  3) لوضع SSH: OpenSSH Client (مثبّت افتراضياً في ويندوز 10/11) ومفتاح SSH
"""
import json
import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse, parse_qs, unquote

try:
    import winreg
    import ctypes
except ImportError:  # للتشغيل خارج ويندوز فقط
    winreg = None

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
XRAY_PATH = os.path.join(BASE_DIR, "xray.exe")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
SOCKS_PORT = 10808
HTTP_PORT = 10809
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW


# ---------------------------------------------------------------- Xray config
def build_xray_config(p):
    """p: قاموس الإعدادات القادمة من الواجهة"""
    proto = p["protocol"]
    if proto == "vless":
        settings = {"vnext": [{"address": p["address"], "port": int(p["port"]),
                               "users": [{"id": p["secret"], "encryption": "none"}]}]}
    elif proto == "vmess":
        settings = {"vnext": [{"address": p["address"], "port": int(p["port"]),
                               "users": [{"id": p["secret"], "security": "auto"}]}]}
    else:  # trojan
        settings = {"servers": [{"address": p["address"], "port": int(p["port"]),
                                 "password": p["secret"]}]}

    stream = {"network": p["network"], "security": "tls" if p["tls"] else "none"}
    if p["tls"]:
        stream["tlsSettings"] = {"serverName": p["sni"] or p["address"],
                                 "allowInsecure": False}
    if p["network"] == "ws":
        stream["wsSettings"] = {"path": p["path"] or "/",
                                "headers": {"Host": p["host"] or p["sni"] or p["address"]}}
    elif p["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": p["path"]}
    elif p["network"] == "tcp" and p.get("payload"):
        # Payload مخصص: ترويسة HTTP تُرسل قبل البيانات (HTTP header obfuscation)
        hosts = [h.strip() for h in p["payload_host"].split(",") if h.strip()]
        stream["tcpSettings"] = {"header": {"type": "http", "request": {
            "version": "1.1", "method": p.get("payload_method", "GET"),
            "path": [p["path"] or "/"],
            "headers": {
                "Host": hosts or [p["address"]],
                "User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
                "Accept-Encoding": ["gzip, deflate"],
                "Connection": ["keep-alive"]}}}}

    outbounds = [{"tag": "proxy", "protocol": proto, "settings": settings,
                  "streamSettings": stream}]

    if p["fragment"]:
        # تجزئة أول حزمة TLS (تفيد ضد بعض أنظمة DPI البسيطة)
        stream["sockopt"] = {"dialerProxy": "fragment"}
        outbounds.append({
            "tag": "fragment", "protocol": "freedom",
            "settings": {"fragment": {"packets": "tlshello",
                                      "length": p["frag_len"],
                                      "interval": p["frag_int"]}},
            "streamSettings": {"sockopt": {"tcpNoDelay": True}}})

    outbounds.append({"tag": "direct", "protocol": "freedom"})

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": SOCKS_PORT,
             "protocol": "socks", "settings": {"udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": HTTP_PORT,
             "protocol": "http"},
        ],
        "outbounds": outbounds,
        "routing": {"rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
    }


def parse_link(link):
    """يقرأ روابط vless:// و trojan:// ويُرجع قاموس حقول"""
    u = urlparse(link.strip())
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    if u.scheme not in ("vless", "trojan"):
        raise ValueError("المدعوم حالياً: vless:// و trojan://")
    return {
        "protocol": u.scheme, "address": u.hostname or "", "port": u.port or 443,
        "secret": unquote(u.username or ""),
        "network": q.get("type", "tcp"),
        "tls": q.get("security", "none") == "tls",
        "sni": q.get("sni", ""), "host": q.get("host", ""),
        "path": unquote(q.get("path", q.get("serviceName", ""))),
    }


# --------------------------------------------------------------- system proxy
def set_system_proxy(enable):
    if winreg is None:
        return
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
    if enable:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                          f"127.0.0.1:{HTTP_PORT}")
    winreg.CloseKey(key)
    # إبلاغ ويندوز بالتغيير
    ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)


# ------------------------------------------------------------------------ GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Personal Proxy")
        self.geometry("520x560")
        self.proc = None
        self.vars = {}

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_x = ttk.Frame(tabs)
        self.tab_s = ttk.Frame(tabs)
        tabs.add(self.tab_x, text="Xray (VLESS / VMess / Trojan)")
        tabs.add(self.tab_s, text="SSH Tunnel")
        self.tabs = tabs

        self.build_xray_tab()
        self.build_ssh_tab()

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=4)
        self.sys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="تمرير كل اتصالات النظام (System Proxy)",
                        variable=self.sys_var).pack(anchor="w")
        self.btn = ttk.Button(bar, text="اتصال", command=self.toggle)
        self.btn.pack(fill="x", pady=4)
        self.status = ttk.Label(bar, text="غير متصل", foreground="gray")
        self.status.pack()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # -- helpers
    def field(self, parent, label, key, default="", row=0, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=3)
        v = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=v, show=show, width=38).grid(
            row=row, column=1, padx=6, pady=3)
        self.vars[key] = v
        return v

    def build_xray_tab(self):
        t = self.tab_x
        ttk.Label(t, text="لصق رابط vless:// أو trojan://").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=6, pady=(8, 0))
        self.link = tk.StringVar()
        ttk.Entry(t, textvariable=self.link, width=48).grid(
            row=1, column=0, columnspan=2, padx=6)
        ttk.Button(t, text="استيراد الرابط", command=self.import_link).grid(
            row=2, column=0, columnspan=2, pady=4)

        ttk.Label(t, text="البروتوكول").grid(row=3, column=0, sticky="w", padx=6)
        self.vars["protocol"] = tk.StringVar(value="vless")
        ttk.Combobox(t, textvariable=self.vars["protocol"], width=35,
                     values=["vless", "vmess", "trojan"], state="readonly").grid(row=3, column=1)
        self.field(t, "العنوان", "address", row=4)
        self.field(t, "المنفذ", "port", "443", row=5)
        self.field(t, "UUID / كلمة السر", "secret", row=6, show="*")
        ttk.Label(t, text="الشبكة").grid(row=7, column=0, sticky="w", padx=6)
        self.vars["network"] = tk.StringVar(value="ws")
        ttk.Combobox(t, textvariable=self.vars["network"], width=35,
                     values=["tcp", "ws", "grpc"], state="readonly").grid(row=7, column=1)
        self.field(t, "المسار / اسم gRPC", "path", "/", row=8)
        self.field(t, "Host (للـ WebSocket)", "host", row=9)
        self.field(t, "SNI", "sni", row=10)
        self.tls = tk.BooleanVar(value=True)
        ttk.Checkbutton(t, text="تفعيل TLS", variable=self.tls).grid(
            row=11, column=0, columnspan=2, sticky="w", padx=6)
        self.frag = tk.BooleanVar(value=False)
        ttk.Checkbutton(t, text="تجزئة حزمة TLS الأولى (Fragment)",
                        variable=self.frag).grid(row=12, column=0, columnspan=2,
                                                 sticky="w", padx=6)
        self.field(t, "طول الأجزاء", "frag_len", "100-200", row=13)
        self.field(t, "الفاصل (ms)", "frag_int", "10-20", row=14)
        self.payload = tk.BooleanVar(value=False)
        ttk.Checkbutton(t, text="Payload مخصص (ترويسة HTTP - شبكة tcp فقط)",
                        variable=self.payload).grid(row=15, column=0, columnspan=2,
                                                    sticky="w", padx=6)
        self.field(t, "Host للـ Payload (افصل بفاصلة)", "payload_host", row=16)
        ttk.Label(t, text="يجب أن يكون السيرفر مضبوطاً بنفس إعداد الترويسة.",
                  foreground="gray").grid(row=17, column=0, columnspan=2)

    def build_ssh_tab(self):
        t = self.tab_s
        self.field(t, "عنوان السيرفر", "ssh_host", row=0)
        self.field(t, "المنفذ", "ssh_port", "22", row=1)
        self.field(t, "المستخدم", "ssh_user", row=2)
        self.field(t, "مسار مفتاح SSH", "ssh_key", row=3)
        ttk.Label(t, text="يفتح نفق SOCKS5 محلي على المنفذ "
                          f"{SOCKS_PORT}.\nيُنصح باستخدام مفتاح بدل كلمة السر.",
                  foreground="gray").grid(row=4, column=0, columnspan=2, pady=10)

    def import_link(self):
        try:
            d = parse_link(self.link.get())
        except Exception as e:
            messagebox.showerror("خطأ", str(e))
            return
        for k in ("protocol", "address", "port", "secret", "network",
                  "path", "host", "sni"):
            self.vars[k].set(str(d[k]))
        self.tls.set(d["tls"])

    # -- connect logic
    def toggle(self):
        if self.proc:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        ssh_mode = self.tabs.index(self.tabs.select()) == 1
        try:
            if ssh_mode:
                v = lambda k: self.vars[k].get().strip()
                cmd = ["ssh", "-N", "-D", f"127.0.0.1:{SOCKS_PORT}",
                       "-p", v("ssh_port"), "-o", "ServerAliveInterval=30",
                       "-o", "ExitOnForwardFailure=yes"]
                if v("ssh_key"):
                    cmd += ["-i", v("ssh_key")]
                cmd.append(f"{v('ssh_user')}@{v('ssh_host')}")
            else:
                if not os.path.exists(XRAY_PATH):
                    raise FileNotFoundError("ضع xray.exe بجانب البرنامج")
                p = {k: self.vars[k].get().strip() for k in
                     ("protocol", "address", "port", "secret", "network",
                      "path", "host", "sni", "frag_len", "frag_int",
                      "payload_host")}
                p["tls"], p["fragment"] = self.tls.get(), self.frag.get()
                p["payload"] = self.payload.get()
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(build_xray_config(p), f, indent=2)
                cmd = [XRAY_PATH, "run", "-c", CONFIG_PATH]

            self.proc = subprocess.Popen(
                cmd, creationflags=NO_WINDOW if os.name == "nt" else 0,
                stderr=subprocess.PIPE)
            self.after(1500, self.check_alive)
            # SOCKS فقط في وضع SSH، لذا نفعّل بروكسي HTTP للنظام في Xray فقط
            if self.sys_var.get() and not ssh_mode:
                set_system_proxy(True)
            self.btn.config(text="قطع الاتصال")
            self.status.config(text="جارٍ الاتصال...", foreground="orange")
        except Exception as e:
            self.proc = None
            messagebox.showerror("خطأ", str(e))

    def check_alive(self):
        if self.proc and self.proc.poll() is not None:
            err = (self.proc.stderr.read() or b"").decode(errors="ignore")[-500:]
            self.proc = None
            set_system_proxy(False)
            self.btn.config(text="اتصال")
            self.status.config(text="فشل الاتصال", foreground="red")
            messagebox.showerror("توقف العملية", err or "توقفت العملية فجأة")
        elif self.proc:
            self.status.config(
                text=f"متصل - SOCKS5 127.0.0.1:{SOCKS_PORT}", foreground="green")

    def disconnect(self):
        if self.proc:
            self.proc.terminate()
            self.proc = None
        set_system_proxy(False)
        self.btn.config(text="اتصال")
        self.status.config(text="غير متصل", foreground="gray")

    def on_close(self):
        self.disconnect()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
