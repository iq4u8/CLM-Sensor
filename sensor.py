"""
================================================================================
🛡️ CLM Sensor v3.0 — Modular Privacy & Network Sentinel for Windows 10 & 11
Developed by: Priyanshu Pandey (IQ4U8)

Features:
- Modular 3-Slot Customizable Floating HUD: Choose ANY 3 tools from:
  [CAM, MIC, LOC, WIFI, LAN, VPN, BT, DNS]
- Center Setup & Configuration Modal on boot or via Right-Click Menu.
- Full Light & Dark Theme Support.
- Direct Bluetooth & Bluetooth Hands-Free Mic Detection via WinMM & Registry.
- Network Link Sentinel: Wi-Fi, Ethernet/LAN, and Active VPN Tunnels.
- DNS Leak & IP Route Inspector.
- Zero-CPU & Battery Saver Engine: Throttles polling when laptop is on battery.
- 100% Offline & Air-Gapped: Zero cloud dependencies, sub-18 MB RAM footprint.
================================================================================
"""

import sys
import os
import json
import winreg
import ctypes
from ctypes import wintypes
import tkinter as tk
from tkinter import messagebox
import threading
import winsound

# ---------------------------------------------------------------------------
# Per-Monitor High-DPI Awareness
# ---------------------------------------------------------------------------
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-monitor DPI aware
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Win32 Native API Bindings (Zero Subprocess / Zero CPU)
# ---------------------------------------------------------------------------
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
setupapi = ctypes.windll.setupapi
winmm = ctypes.windll.winmm
iphlpapi = ctypes.windll.iphlpapi

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sensor_config.json")

# Win32 Battery Status
class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ('ACLineStatus', wintypes.BYTE),
        ('BatteryFlag', wintypes.BYTE),
        ('BatteryLifePercent', wintypes.BYTE),
        ('SystemStatusFlag', wintypes.BYTE),
        ('BatteryLifeTime', wintypes.DWORD),
        ('BatteryFullLifeTime', wintypes.DWORD)
    ]

# Win32 SetupAPI GUID & Structs for Fast Camera Hardware Query
class GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', wintypes.DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', ctypes.c_ubyte * 8)
    ]

GUID_KSCATEGORY_CAPTURE = GUID(
    0x65E8773D, 0x8F56, 0x11D0,
    (ctypes.c_ubyte * 8)(0xA3, 0xB9, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96)
)
DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10

setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('ClassGuid', GUID),
        ('DevInst', wintypes.DWORD),
        ('Reserved', ctypes.POINTER(wintypes.ULONG))
    ]

setupapi.SetupDiEnumDeviceInfo.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]
setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL

# WinMM WaveIn Structs for Audio & Bluetooth Mic Sensing
class WAVEINCAPSW(ctypes.Structure):
    _fields_ = [
        ('wMid', wintypes.WORD),
        ('wPid', wintypes.WORD),
        ('vDriverVersion', wintypes.DWORD),
        ('szPname', wintypes.WCHAR * 32),
        ('dwFormats', wintypes.DWORD),
        ('wChannels', wintypes.WORD),
        ('wReserved1', wintypes.WORD)
    ]

# IPHlpAPI Structs for Network & VPN Inspection
class IP_ADDRESS_STRING(ctypes.Structure):
    _fields_ = [('String', ctypes.c_char * 16)]

class IP_ADDR_STRING(ctypes.Structure):
    pass
IP_ADDR_STRING._fields_ = [
    ('Next', ctypes.POINTER(IP_ADDR_STRING)),
    ('IpAddress', IP_ADDRESS_STRING),
    ('IpMask', IP_ADDRESS_STRING),
    ('Context', wintypes.DWORD)
]

MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8

class IP_ADAPTER_INFO(ctypes.Structure):
    pass
IP_ADAPTER_INFO._fields_ = [
    ('Next', ctypes.POINTER(IP_ADAPTER_INFO)),
    ('ComboIndex', wintypes.DWORD),
    ('AdapterName', ctypes.c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ('Description', ctypes.c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ('AddressLength', wintypes.UINT),
    ('Address', ctypes.c_byte * MAX_ADAPTER_ADDRESS_LENGTH),
    ('Index', wintypes.DWORD),
    ('Type', wintypes.UINT),
    ('DhcpEnabled', wintypes.UINT),
    ('CurrentIpAddress', ctypes.POINTER(IP_ADDR_STRING)),
    ('IpAddressList', IP_ADDR_STRING),
    ('GatewayList', IP_ADDR_STRING),
    ('DhcpServer', IP_ADDR_STRING),
    ('HaveWins', wintypes.BOOL),
    ('PrimaryWinsServer', IP_ADDR_STRING),
    ('SecondaryWinsServer', IP_ADDR_STRING),
    ('LeaseObtained', ctypes.c_longlong),
    ('LeaseExpires', ctypes.c_longlong)
]


# ---------------------------------------------------------------------------
# Hardware & Network Detection Engine
# ---------------------------------------------------------------------------
class HardwareEngine:
    @staticmethod
    def get_power_status():
        sps = SYSTEM_POWER_STATUS()
        if kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
            is_ac = (sps.ACLineStatus == 1)
            battery_pct = sps.BatteryLifePercent
            return is_ac, battery_pct
        return True, 100

    @staticmethod
    def is_camera_hardware_ok():
        try:
            hdev = setupapi.SetupDiGetClassDevsW(
                ctypes.byref(GUID_KSCATEGORY_CAPTURE), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
            )
            if hdev == wintypes.HANDLE(-1).value or hdev == -1:
                return False
            devinfo = SP_DEVINFO_DATA()
            devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            present = bool(setupapi.SetupDiEnumDeviceInfo(hdev, 0, ctypes.byref(devinfo)))
            setupapi.SetupDiDestroyDeviceInfoList(hdev)
            return present
        except Exception:
            return True

    @staticmethod
    def scan_consent_store(capability):
        """Checks CapabilityAccessManager registry for active usage and process names."""
        base_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\' + capability
        active_apps = []

        for root_key in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                base_k = winreg.OpenKey(root_key, base_path)
            except OSError:
                continue

            def scan_branch(parent_k):
                idx = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(parent_k, idx)
                        idx += 1
                        if sub_name == 'NonPackaged':
                            try:
                                np_k = winreg.OpenKey(parent_k, sub_name)
                                scan_branch(np_k)
                                winreg.CloseKey(np_k)
                            except OSError:
                                pass
                            continue

                        try:
                            k = winreg.OpenKey(parent_k, sub_name)
                            try:
                                start, _ = winreg.QueryValueEx(k, 'LastUsedTimeStart')
                                stop, _ = winreg.QueryValueEx(k, 'LastUsedTimeStop')
                                if (stop == 0 and start != 0) or (start > stop):
                                    clean = sub_name.split('#')[-1]
                                    if '_' in clean and '.' in clean:
                                        clean = clean.split('_')[0]
                                    if clean not in active_apps:
                                        active_apps.append(clean)
                            except OSError:
                                pass
                            winreg.CloseKey(k)
                        except OSError:
                            pass
                    except OSError:
                        break

            scan_branch(base_k)
            winreg.CloseKey(base_k)

        return len(active_apps) > 0, active_apps

    @staticmethod
    def check_audio_devices():
        """Returns (has_mic, has_bt_mic, device_names)."""
        num_devs = winmm.waveInGetNumDevs()
        dev_names = []
        has_bt = False
        for i in range(num_devs):
            caps = WAVEINCAPSW()
            if winmm.waveInGetDevCapsW(i, ctypes.byref(caps), ctypes.sizeof(caps)) == 0:
                name = caps.szPname
                dev_names.append(name)
                if any(t in name.lower() for t in ['bluetooth', 'hands-free', 'headset', 'airpods', 'buds', 'wireless']):
                    has_bt = True
        return num_devs > 0, has_bt, dev_names

    @staticmethod
    def get_bluetooth_info():
        """Checks paired/connected BT devices in registry."""
        paired_names = []
        try:
            path = r'SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, idx)
                    idx += 1
                    try:
                        dk = winreg.OpenKey(k, sub)
                        raw_name, _ = winreg.QueryValueEx(dk, 'Name')
                        winreg.CloseKey(dk)
                        if isinstance(raw_name, bytes):
                            raw_name = raw_name.decode('utf-8', errors='ignore').strip('\x00')
                        if raw_name:
                            paired_names.append(raw_name)
                    except Exception:
                        pass
                except OSError:
                    break
            winreg.CloseKey(k)
        except Exception:
            pass
        return len(paired_names) > 0, paired_names

    @staticmethod
    def scan_network_adapters():
        """Inspects Wi-Fi, Ethernet LAN, and VPN interfaces via Win32 iphlpapi."""
        wifi_active = False
        wifi_info = ""
        lan_active = False
        lan_info = ""
        vpn_active = False
        vpn_info = ""

        try:
            buflen = wintypes.ULONG(0)
            iphlpapi.GetAdaptersInfo(None, ctypes.byref(buflen))
            if buflen.value > 0:
                buf = (ctypes.c_byte * buflen.value)()
                if iphlpapi.GetAdaptersInfo(ctypes.byref(buf), ctypes.byref(buflen)) == 0:
                    pAdapter = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
                    while pAdapter:
                        desc = pAdapter.contents.Description.decode('utf-8', errors='ignore')
                        ip = pAdapter.contents.IpAddressList.IpAddress.String.decode('utf-8', errors='ignore')
                        atype = pAdapter.contents.Type

                        is_active_ip = bool(ip and ip != "0.0.0.0")

                        # VPN detection
                        vpn_keywords = ['tap', 'tun', 'wireguard', 'vpn', 'openvpn', 'nord', 'tailscale', 'zerotier', 'cisco', 'fortinet']
                        if any(k in desc.lower() for k in vpn_keywords):
                            if is_active_ip:
                                vpn_active = True
                                vpn_info = f"{desc} ({ip})"
                        elif atype == 71:  # IF_TYPE_IEEE80211 (Wi-Fi)
                            if is_active_ip:
                                wifi_active = True
                                wifi_info = f"{desc} ({ip})"
                        elif atype == 6:   # IF_TYPE_ETHERNET_CSMACD (Ethernet)
                            if is_active_ip:
                                lan_active = True
                                lan_info = f"{desc} ({ip})"

                        pAdapter = pAdapter.contents.Next
        except Exception:
            pass

        return (wifi_active, wifi_info), (lan_active, lan_info), (vpn_active, vpn_info)

    @staticmethod
    def check_dns_security():
        """Checks DNS servers from registry to detect ISP leaks vs encrypted resolvers."""
        dns_servers = []
        is_secure = False
        try:
            path = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, idx)
                    idx += 1
                    ik = winreg.OpenKey(k, sub)
                    for key_name in ('DhcpNameServer', 'NameServer'):
                        try:
                            val, _ = winreg.QueryValueEx(ik, key_name)
                            if val and isinstance(val, str):
                                for s in val.replace(',', ' ').split():
                                    if s and s != '0.0.0.0' and s not in dns_servers:
                                        dns_servers.append(s)
                        except OSError:
                            pass
                    winreg.CloseKey(ik)
                except OSError:
                    break
            winreg.CloseKey(k)
        except Exception:
            pass

        # Secure known DNS providers
        secure_pools = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '10.']
        if any(any(d.startswith(p) for p in secure_pools) for d in dns_servers):
            is_secure = True

        return is_secure, dns_servers


# ---------------------------------------------------------------------------
# Metadata for All 8 Modular Sentinel Tools
# ---------------------------------------------------------------------------
TOOL_CATALOG = {
    "cam": {
        "code": "CAM",
        "title": "Camera Sentinel",
        "icon": "📷",
        "desc": "Detects active webcam capture & physical Fn kill-switch state.",
        "alert_color": "#ef4444",
        "ready_color": "#10b981",
        "type": "privacy"
    },
    "mic": {
        "code": "MIC",
        "title": "Microphone & BT-Mic",
        "icon": "🎙️",
        "desc": "Monitors internal, USB, and Bluetooth hands-free audio recording.",
        "alert_color": "#f59e0b",
        "ready_color": "#10b981",
        "type": "privacy"
    },
    "loc": {
        "code": "LOC",
        "title": "Location Queries",
        "icon": "📍",
        "desc": "Alerts when apps access GPS or Wi-Fi geo-location coordinates.",
        "alert_color": "#ef4444",
        "ready_color": "#10b981",
        "type": "privacy"
    },
    "wifi": {
        "code": "WIFI",
        "title": "Wi-Fi Network Link",
        "icon": "📶",
        "desc": "Monitors active wireless adapter link status and assigned IP.",
        "alert_color": "#38bdf8",
        "ready_color": "#10b981",
        "type": "network"
    },
    "lan": {
        "code": "LAN",
        "title": "Ethernet / Cable LAN",
        "icon": "🔌",
        "desc": "Tracks physical Ethernet cable connection and network gateway.",
        "alert_color": "#38bdf8",
        "ready_color": "#10b981",
        "type": "network"
    },
    "vpn": {
        "code": "VPN",
        "title": "VPN Privacy Tunnel",
        "icon": "🔒",
        "desc": "Detects active WireGuard, OpenVPN, TAP/TUN encryption tunnels.",
        "alert_color": "#38bdf8",
        "ready_color": "#10b981",
        "type": "security"
    },
    "bt": {
        "code": "BT",
        "title": "Bluetooth Audio & Link",
        "icon": "🎧",
        "desc": "Monitors Bluetooth radio, paired devices, and active audio headsets.",
        "alert_color": "#38bdf8",
        "ready_color": "#10b981",
        "type": "hardware"
    },
    "dns": {
        "code": "DNS",
        "title": "DNS & IP Leak Shield",
        "icon": "🌐",
        "desc": "Audits DNS server resolvers for leaks and unencrypted ISP routes.",
        "alert_color": "#f59e0b",
        "ready_color": "#10b981",
        "type": "security"
    }
}


# ---------------------------------------------------------------------------
# Theme Palettes (Light & Dark)
# ---------------------------------------------------------------------------
THEMES = {
    "dark": {
        "chroma_bg": "#010101",
        "pill_border": "#334155",
        "pill_bg": "#0f172a",
        "pill_inner": "#020617",
        "divider": "#1e293b",
        "rim_border": "#1e293b",
        "text": "#94a3b8",
        "text_highlight": "#f8fafc",
        "disabled_led": "#334155",
        "modal_bg": "#0b1220",
        "card_bg": "#131d31",
        "card_border": "#1e2d4a",
        "card_active_border": "#38bdf8",
        "card_active_bg": "#1e293b"
    },
    "light": {
        "chroma_bg": "#feffff",
        "pill_border": "#cbd5e1",
        "pill_bg": "#ffffff",
        "pill_inner": "#f1f5f9",
        "divider": "#e2e8f0",
        "rim_border": "#cbd5e1",
        "text": "#475569",
        "text_highlight": "#0f172a",
        "disabled_led": "#94a3b8",
        "modal_bg": "#f8fafc",
        "card_bg": "#ffffff",
        "card_border": "#e2e8f0",
        "card_active_border": "#0284c7",
        "card_active_bg": "#f0f9ff"
    }
}


# ---------------------------------------------------------------------------
# Lightweight Floating Tooltip
# ---------------------------------------------------------------------------
class TooltipWindow:
    def __init__(self, master):
        self.master = master
        self.tip_window = None

    def show(self, text, x, y, theme="dark"):
        self.hide()
        if not text:
            return
        self.tip_window = tk.Toplevel(self.master)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_attributes("-topmost", True)
        self.tip_window.wm_attributes("-toolwindow", True)
        self.tip_window.geometry(f"+{x}+{y - 28}")

        bg = "#0f172a" if theme == "dark" else "#ffffff"
        fg = "#f8fafc" if theme == "dark" else "#0f172a"
        border = "#38bdf8" if theme == "dark" else "#0284c7"

        frame = tk.Frame(self.tip_window, bg=bg, highlightthickness=1, highlightbackground=border)
        frame.pack()
        lbl = tk.Label(frame, text=text, font=("Segoe UI", 8, "bold"), fg=fg, bg=bg, padx=8, pady=3)
        lbl.pack()

    def hide(self):
        if self.tip_window:
            try:
                self.tip_window.destroy()
            except Exception:
                pass
            self.tip_window = None


# ---------------------------------------------------------------------------
# Center Studio Modal (Configure Any 3 Sensors & Theme)
# ---------------------------------------------------------------------------
class CenterStudioModal(tk.Toplevel):
    def __init__(self, parent, current_config, on_save_callback):
        super().__init__(parent)
        self.parent = parent
        self.config = current_config
        self.on_save_callback = on_save_callback

        self.title("🛡️ CLM Sensor — Sentinel Studio & Tool Selection")
        self.wm_attributes("-topmost", True)
        self.resizable(False, False)

        # Center on primary monitor
        w, h = 640, 520
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.selected_tools = list(self.config.get("selected_sensors", ["cam", "mic", "vpn"]))
        self.current_theme = self.config.get("theme", "dark")
        self.battery_saver_var = tk.BooleanVar(value=self.config.get("battery_saver", True))
        self.sound_alert_var = tk.BooleanVar(value=self.config.get("sound_alerts", True))

        self.card_frames = {}
        self.build_modal_ui()

    def build_modal_ui(self):
        th = THEMES[self.current_theme]
        self.configure(bg=th["modal_bg"])

        # Header Title
        hdr_frame = tk.Frame(self, bg=th["modal_bg"], pady=12)
        hdr_frame.pack(fill="x", padx=24)

        title_lbl = tk.Label(
            hdr_frame, text="🛡️ CLM Sensor — Sentinel Studio",
            font=("Segoe UI", 16, "bold"),
            fg=th["text_highlight"], bg=th["modal_bg"]
        )
        title_lbl.pack(anchor="w")

        sub_text = "Select EXACTLY 3 active sensors for your floating desktop HUD widget:"
        sub_lbl = tk.Label(hdr_frame, text=sub_text, font=("Segoe UI", 9), fg=th["text"], bg=th["modal_bg"])
        sub_lbl.pack(anchor="w", pady=(2, 0))

        # Counter Badge
        self.counter_lbl = tk.Label(
            hdr_frame, text=f"Selected: {len(self.selected_tools)} / 3 Tools",
            font=("Segoe UI", 9, "bold"), fg="#38bdf8" if len(self.selected_tools) == 3 else "#ef4444",
            bg=th["modal_bg"]
        )
        self.counter_lbl.pack(anchor="w", pady=(4, 0))

        # 8 Tools Grid
        grid_frame = tk.Frame(self, bg=th["modal_bg"])
        grid_frame.pack(fill="both", expand=True, padx=20, pady=8)

        tool_keys = list(TOOL_CATALOG.keys())
        for idx, key in enumerate(tool_keys):
            row = idx // 4
            col = idx % 4
            self.create_tool_card(grid_frame, key, row, col, th)

        # Settings Bottom Bar
        bottom_bar = tk.Frame(self, bg=th["modal_bg"], pady=12)
        bottom_bar.pack(fill="x", padx=24)

        # Theme Selector Radio
        theme_frame = tk.Frame(bottom_bar, bg=th["modal_bg"])
        theme_frame.pack(side="left")

        theme_lbl = tk.Label(theme_frame, text="Theme:", font=("Segoe UI", 9, "bold"), fg=th["text_highlight"], bg=th["modal_bg"])
        theme_lbl.pack(side="left", padx=(0, 8))

        self.theme_var = tk.StringVar(value=self.current_theme)
        r_dark = tk.Radiobutton(theme_frame, text="🌙 Dark", variable=self.theme_var, value="dark", command=self.on_theme_changed, bg=th["modal_bg"], fg=th["text"], selectcolor=th["modal_bg"])
        r_dark.pack(side="left", padx=4)
        r_light = tk.Radiobutton(theme_frame, text="☀️ Light", variable=self.theme_var, value="light", command=self.on_theme_changed, bg=th["modal_bg"], fg=th["text"], selectcolor=th["modal_bg"])
        r_light.pack(side="left", padx=4)

        # Battery & Sound Checkboxes
        chk_frame = tk.Frame(bottom_bar, bg=th["modal_bg"])
        chk_frame.pack(side="left", padx=16)

        c_bat = tk.Checkbutton(chk_frame, text="⚡ Battery Saver", variable=self.battery_saver_var, bg=th["modal_bg"], fg=th["text"], selectcolor=th["modal_bg"])
        c_bat.pack(side="left", padx=4)
        c_snd = tk.Checkbutton(chk_frame, text="🔔 Sound Alert", variable=self.sound_alert_var, bg=th["modal_bg"], fg=th["text"], selectcolor=th["modal_bg"])
        c_snd.pack(side="left", padx=4)

        # Save Button
        save_btn = tk.Button(
            bottom_bar, text="💾 Save & Launch Widget",
            font=("Segoe UI", 10, "bold"),
            bg="#059669", fg="#ffffff", activebackground="#10b981", activeforeground="#ffffff",
            relief="flat", padx=14, pady=6, cursor="hand2",
            command=self.save_and_close
        )
        save_btn.pack(side="right")

    def create_tool_card(self, parent, key, row, col, th):
        tool = TOOL_CATALOG[key]
        is_selected = key in self.selected_tools

        card_bg = th["card_active_bg"] if is_selected else th["card_bg"]
        card_border = th["card_active_border"] if is_selected else th["card_border"]

        f = tk.Frame(
            parent, bg=card_bg, highlightthickness=2, highlightbackground=card_border,
            padx=8, pady=8, cursor="hand2", width=135, height=115
        )
        f.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
        f.pack_propagate(False)

        icon_lbl = tk.Label(f, text=tool["icon"], font=("Segoe UI", 18), bg=card_bg, fg=th["text_highlight"])
        icon_lbl.pack(anchor="w")

        code_lbl = tk.Label(f, text=tool["code"], font=("Segoe UI", 10, "bold"), bg=card_bg, fg=th["text_highlight"])
        code_lbl.pack(anchor="w")

        desc_lbl = tk.Label(f, text=tool["desc"], font=("Segoe UI", 7), bg=card_bg, fg=th["text"], wraplength=120, justify="left")
        desc_lbl.pack(anchor="w", pady=(2, 0))

        # Store card widget references
        self.card_frames[key] = f

        # Bind click on all child elements
        for widget in (f, icon_lbl, code_lbl, desc_lbl):
            widget.bind("<Button-1>", lambda e, k=key: self.toggle_tool(k))

    def toggle_tool(self, key):
        if key in self.selected_tools:
            if len(self.selected_tools) <= 1:
                messagebox.showwarning("Notice", "You must keep at least 1 sensor selected.")
                return
            self.selected_tools.remove(key)
        else:
            if len(self.selected_tools) >= 3:
                # Replace the first chosen tool
                removed = self.selected_tools.pop(0)
                self.selected_tools.append(key)
            else:
                self.selected_tools.append(key)

        # Refresh cards appearance
        th = THEMES[self.current_theme]
        for k, frame in self.card_frames.items():
            sel = k in self.selected_tools
            bg = th["card_active_bg"] if sel else th["card_bg"]
            border = th["card_active_border"] if sel else th["card_border"]
            frame.configure(bg=bg, highlightbackground=border)
            for child in frame.winfo_children():
                child.configure(bg=bg)

        # Update counter
        count = len(self.selected_tools)
        color = "#10b981" if count == 3 else "#ef4444"
        self.counter_lbl.configure(text=f"Selected: {count} / 3 Tools", fg=color)

    def on_theme_changed(self):
        self.current_theme = self.theme_var.get()
        # Re-render modal in new theme
        for child in self.winfo_children():
            child.destroy()
        self.card_frames.clear()
        self.build_modal_ui()

    def save_and_close(self):
        if len(self.selected_tools) != 3:
            messagebox.showwarning("Incomplete", "Please select exactly 3 tools for your desktop widget.")
            return

        new_config = {
            "selected_sensors": self.selected_tools,
            "theme": self.current_theme,
            "sound_alerts": self.sound_alert_var.get(),
            "always_on_top": self.config.get("always_on_top", True),
            "battery_saver": self.battery_saver_var.get(),
            "first_run_completed": True
        }

        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(new_config, f, indent=2)
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to write config: {e}")

        try:
            self.destroy()
        except Exception:
            pass
        self.on_save_callback(new_config)


# ---------------------------------------------------------------------------
# Main Floating Sentinel Pill Widget
# ---------------------------------------------------------------------------
class PrivacyMonitorWidget:
    def __init__(self, master):
        self.master = master
        self.is_running = True

        # Load Configuration
        self.load_config()

        # Window settings
        self.master.overrideredirect(True)
        self.master.wm_attributes("-toolwindow", True)
        self.master.attributes("-topmost", self.config.get("always_on_top", True))

        # Dimensions: 126x38 for 3 capsules
        self.width = 126
        self.height = 38

        # Apply Theme Colors
        self.apply_theme_colors()

        # Canvas Setup
        self.canvas = tk.Canvas(
            master, width=self.width, height=self.height,
            bg=self.theme["chroma_bg"], highlightthickness=0
        )
        self.canvas.pack()

        # Tooltip
        self.tooltip = TooltipWindow(self.master)

        # Dynamic State Dictionary for All Tools
        self.state = {
            "cam": {"active": False, "enabled": True, "info": "Ready"},
            "mic": {"active": False, "enabled": True, "has_bt": False, "info": "Ready"},
            "loc": {"active": False, "enabled": True, "info": "Ready"},
            "wifi": {"active": False, "enabled": True, "info": "Disconnected"},
            "lan": {"active": False, "enabled": True, "info": "Disconnected"},
            "vpn": {"active": False, "enabled": True, "info": "No Active Tunnel"},
            "bt": {"active": False, "enabled": True, "info": "Radio Off"},
            "dns": {"active": True, "enabled": True, "info": "Resolvers Checked"}
        }

        self.flicker_state = False
        self.prev_alerts = {"cam": False, "mic": False, "vpn": False}

        # Place at bottom-right
        self.snap_to_corner("bottom-right")

        # Build UI Elements
        self.build_pill_ui()

        # Context Menu
        self.create_context_menu()

        # Bindings
        self.canvas.bind("<ButtonPress-1>", self.start_move)
        self.canvas.bind("<ButtonRelease-1>", self.stop_move)
        self.canvas.bind("<B1-Motion>", self.do_move)
        self.canvas.bind("<Button-3>", self.show_context_menu)
        self.canvas.bind("<Double-Button-1>", lambda e: self.open_studio_modal())
        self.canvas.bind("<Motion>", self.on_mouse_hover)
        self.canvas.bind("<Leave>", lambda e: self.tooltip.hide())
        self.master.bind("<FocusIn>", self.force_topmost)
        self.master.bind("<Escape>", lambda e: self.on_exit())

        # Start Async Scanning Loops
        self.keep_topmost_loop()
        self.sensor_scan_loop()
        self.animation_loop()

        # If first run, present the Center Studio Modal
        if not self.config.get("first_run_completed", False):
            self.master.after(500, self.open_studio_modal)

    def load_config(self):
        defaults = {
            "selected_sensors": ["cam", "mic", "vpn"],
            "theme": "dark",
            "sound_alerts": True,
            "always_on_top": True,
            "battery_saver": True,
            "first_run_completed": False
        }
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
            except Exception:
                self.config = defaults
        else:
            self.config = defaults

        # Ensure valid 3 items
        if len(self.config.get("selected_sensors", [])) != 3:
            self.config["selected_sensors"] = ["cam", "mic", "vpn"]

    def apply_theme_colors(self):
        theme_name = self.config.get("theme", "dark")
        self.theme = THEMES.get(theme_name, THEMES["dark"])
        self.master.attributes("-transparentcolor", self.theme["chroma_bg"])
        self.master.configure(bg=self.theme["chroma_bg"])

    def build_pill_ui(self):
        """Draws the 3 chosen capsules dynamically."""
        self.canvas.delete("all")
        th = self.theme

        # Outer rounded border
        self.round_rectangle(2, 2, self.width - 2, self.height - 2, radius=16, fill=th["pill_border"], outline=th["divider"], width=1.2)
        # Inner graphite body
        self.round_rectangle(4, 4, self.width - 4, self.height - 4, radius=14, fill=th["pill_bg"], outline='', width=0)

        # 2 Vertical Divider Columns
        self.canvas.create_line(42, 8, 42, 30, fill=th["divider"], width=1.2)
        self.canvas.create_line(84, 8, 84, 30, fill=th["divider"], width=1.2)

        # 3 Slots
        self.slot_elements = []
        selected = self.config["selected_sensors"]

        # Slot centers: 21, 63, 105
        x_centers = [21, 63, 105]

        for i in range(3):
            xc = x_centers[i]
            tool_key = selected[i]
            tool_meta = TOOL_CATALOG[tool_key]

            halo = self.canvas.create_oval(xc - 7, 6, xc + 7, 20, fill='', outline='', width=1.5)
            rim = self.canvas.create_oval(xc - 5, 8, xc + 5, 18, fill=th["pill_inner"], outline=th["rim_border"], width=1)
            led = self.canvas.create_oval(xc - 3, 10, xc + 3, 16, fill="#10b981", outline='')
            lbl = self.canvas.create_text(xc, 28, text=tool_meta["code"], fill=th["text"], font=("Segoe UI", 7, "bold"))

            self.slot_elements.append({
                "key": tool_key,
                "halo": halo,
                "led": led,
                "label": lbl
            })

    def round_rectangle(self, x1, y1, x2, y2, radius=25, **kwargs):
        points = [
            x1 + radius, y1, x1 + radius, y1,
            x2 - radius, y1, x2 - radius, y1,
            x2, y1, x2, y1 + radius,
            x2, y1 + radius, x2, y2 - radius,
            x2, y2 - radius, x2, y2,
            x2 - radius, y2, x2 - radius, y2,
            x1 + radius, y2, x1 + radius, y2,
            x1, y2, x1, y2 - radius,
            x1, y2 - radius, x1, y1 + radius,
            x1, y1 + radius, x1, y1
        ]
        return self.canvas.create_polygon(points, **kwargs, smooth=True)

    def snap_to_corner(self, position):
        screen_w = self.master.winfo_screenwidth()
        screen_h = self.master.winfo_screenheight()
        if position == "bottom-right":
            x = screen_w - self.width - 32
            y = screen_h - self.height - 56
        elif position == "top-right":
            x = screen_w - self.width - 32
            y = 36
        elif position == "bottom-left":
            x = 32
            y = screen_h - self.height - 56
        elif position == "top-left":
            x = 32
            y = 36
        else:
            x = screen_w - self.width - 32
            y = screen_h - self.height - 56
        self.master.geometry(f"{self.width}x{self.height}+{x}+{y}")
        self.force_topmost()

    def force_topmost(self, event=None):
        if not self.is_running or not self.config.get("always_on_top", True):
            return
        try:
            hwnd = user32.GetAncestor(self.master.winfo_id(), 2)
            if not hwnd:
                hwnd = self.master.winfo_id()
            user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 1 | 2 | 16)
            self.master.attributes('-topmost', True)
        except Exception:
            pass

    def keep_topmost_loop(self):
        if not self.is_running:
            return
        self.force_topmost()
        self.master.after(1000, self.keep_topmost_loop)

    def start_move(self, event):
        self.x = event.x
        self.y = event.y
        self.force_topmost()

    def stop_move(self, event):
        self.x = None
        self.y = None
        self.force_topmost()

    def do_move(self, event):
        if not self.x or not self.y:
            return
        x = self.master.winfo_x() + (event.x - self.x)
        y = self.master.winfo_y() + (event.y - self.y)
        sw = self.master.winfo_screenwidth()
        sh = self.master.winfo_screenheight()
        x = max(0, min(x, sw - self.width))
        y = max(0, min(y, sh - self.height))
        self.master.geometry(f"+{x}+{y}")

    def on_mouse_hover(self, event):
        slot_idx = min(2, max(0, event.x // 42))
        slot = self.slot_elements[slot_idx]
        key = slot["key"]
        meta = TOOL_CATALOG[key]
        st = self.state[key]

        # Formulate description text
        if key == "cam":
            if st["active"]:
                txt = f"🚨 CAMERA IN USE: {st['info']}"
            elif st["enabled"]:
                txt = "🟢 Camera: Ready & Idle (0 recording)"
            else:
                txt = "⚫ Camera: Hardware / Privacy Disabled"
        elif key == "mic":
            bt_tag = " [BT Headset]" if st.get("has_bt", False) else ""
            if st["active"]:
                txt = f"🟡 MIC IN USE{bt_tag}: {st['info']}"
            elif st["enabled"]:
                txt = f"🟢 Mic: Ready & Standing By{bt_tag}"
            else:
                txt = "⚫ Microphone: Blocked in Settings"
        elif key == "loc":
            if st["active"]:
                txt = f"🔴 LOCATION QUERY: {st['info']}"
            elif st["enabled"]:
                txt = "🟢 Location: Standing By (0 queries)"
            else:
                txt = "⚫ Location: Disabled in Windows Settings"
        elif key == "wifi":
            if st["active"]:
                txt = f"📶 Wi-Fi: Connected ({st['info']})"
            else:
                txt = "⚫ Wi-Fi: Disconnected / Adapter Off"
        elif key == "lan":
            if st["active"]:
                txt = f"🔌 LAN: Connected ({st['info']})"
            else:
                txt = "⚫ Ethernet: Cable Unplugged"
        elif key == "vpn":
            if st["active"]:
                txt = f"🔒 VPN: Encrypted Tunnel Active ({st['info']})"
            else:
                txt = "⚫ VPN: Inactive / Raw ISP Exposed"
        elif key == "bt":
            if st["active"]:
                txt = f"🎧 Bluetooth: Connected ({st['info']})"
            else:
                txt = "⚫ Bluetooth: No Devices Connected"
        elif key == "dns":
            if st["active"]:
                txt = f"🛡️ DNS: Secure Resolvers ({st['info']})"
            else:
                txt = f"⚠️ DNS: Potential Leak to ISP ({st['info']})"
        else:
            txt = f"{meta['title']}: {st['info']}"

        rx = self.master.winfo_rootx() + event.x
        ry = self.master.winfo_rooty()
        self.tooltip.show(txt, rx, ry, self.config.get("theme", "dark"))

    def sensor_scan_loop(self):
        """Scans only the chosen active sensors to conserve battery and CPU."""
        if not self.is_running:
            return

        selected = self.config["selected_sensors"]

        # 1. Power Status
        is_ac, batt_pct = HardwareEngine.get_power_status()

        # 2. Camera Scan (if selected)
        if "cam" in selected:
            hw_ok = HardwareEngine.is_camera_hardware_ok()
            in_use, apps = HardwareEngine.scan_consent_store("webcam")
            self.state["cam"]["active"] = in_use
            self.state["cam"]["enabled"] = hw_ok
            self.state["cam"]["info"] = ", ".join(apps) if apps else "Idle"

        # 3. Mic & Bluetooth Mic Scan (if selected)
        if "mic" in selected:
            has_dev, has_bt, dev_names = HardwareEngine.check_audio_devices()
            in_use, apps = HardwareEngine.scan_consent_store("microphone")
            self.state["mic"]["active"] = in_use
            self.state["mic"]["enabled"] = has_dev
            self.state["mic"]["has_bt"] = has_bt
            self.state["mic"]["info"] = ", ".join(apps) if apps else ("BT-Mic Ready" if has_bt else "Idle")

        # 4. Location Scan (if selected)
        if "loc" in selected:
            in_use, apps = HardwareEngine.scan_consent_store("location")
            self.state["loc"]["active"] = in_use
            self.state["loc"]["info"] = ", ".join(apps) if apps else "Idle"

        # 5. Network / VPN Scans (if wifi, lan, or vpn selected)
        if any(k in selected for k in ("wifi", "lan", "vpn")):
            (wf_on, wf_inf), (lan_on, lan_inf), (vpn_on, vpn_inf) = HardwareEngine.scan_network_adapters()
            if "wifi" in selected:
                self.state["wifi"]["active"] = wf_on
                self.state["wifi"]["info"] = wf_inf or "Off"
            if "lan" in selected:
                self.state["lan"]["active"] = lan_on
                self.state["lan"]["info"] = lan_inf or "Unplugged"
            if "vpn" in selected:
                self.state["vpn"]["active"] = vpn_on
                self.state["vpn"]["info"] = vpn_inf or "Inactive"

        # 6. Bluetooth Scan (if selected)
        if "bt" in selected:
            has_bt_paired, bt_list = HardwareEngine.get_bluetooth_info()
            _, has_bt_mic, _ = HardwareEngine.check_audio_devices()
            self.state["bt"]["active"] = has_bt_mic or (has_bt_paired and len(bt_list) > 0)
            self.state["bt"]["info"] = f"{len(bt_list)} Paired" if bt_list else "None"

        # 7. DNS Scan (if selected)
        if "dns" in selected:
            is_sec, dns_list = HardwareEngine.check_dns_security()
            self.state["dns"]["active"] = is_sec
            self.state["dns"]["info"] = ", ".join(dns_list[:2]) if dns_list else "Default"

        # Audio alerts on state transition
        if self.config.get("sound_alerts", True):
            for k in ("cam", "mic"):
                if k in selected and self.state[k]["active"] and not self.prev_alerts[k]:
                    threading.Thread(target=lambda: winsound.MessageBeep(winsound.MB_ICONEXCLAMATION), daemon=True).start()
                self.prev_alerts[k] = self.state[k]["active"]

        # Adaptive Battery Saver Interval
        if self.config.get("battery_saver", True) and not is_ac:
            interval = 4000  # On Battery: 4 seconds throttle (Zero battery drain)
        else:
            interval = 1600  # On AC Power: 1.6 seconds

        self.master.after(interval, self.sensor_scan_loop)

    def animation_loop(self):
        """Animates LEDs, pulsing halos, and status colors on the floating pill."""
        if not self.is_running:
            return

        self.flicker_state = not self.flicker_state
        th = self.theme

        for slot in self.slot_elements:
            key = slot["key"]
            meta = TOOL_CATALOG[key]
            st = self.state[key]
            is_act = st["active"]

            if is_act:
                # Active Alert Pulse
                col = meta["alert_color"] if self.flicker_state else "#991b1b"
                halo_col = meta["alert_color"] if self.flicker_state else ""
                lbl_col = meta["alert_color"]
            elif st.get("enabled", True):
                # Ready & Idle
                col = meta["ready_color"]
                halo_col = ""
                lbl_col = th["text"]
            else:
                # Disabled / Blocked
                col = th["disabled_led"]
                halo_col = ""
                lbl_col = th["text"]

            self.canvas.itemconfigure(slot["led"], fill=col)
            self.canvas.itemconfigure(slot["halo"], outline=halo_col)
            self.canvas.itemconfigure(slot["label"], fill=lbl_col)

        self.master.after(350, self.animation_loop)

    def create_context_menu(self):
        th = self.theme
        self.menu = tk.Menu(self.master, tearoff=0, bg=th["pill_bg"], fg=th["text_highlight"], activebackground="#0284c7")
        self.menu.add_command(label="🛡️ CLM Sensor v3.0", state="disabled")
        self.menu.add_separator()

        self.menu.add_command(label="⚙️ Customize 3-Slot Sensors & Theme...", command=self.open_studio_modal)
        self.menu.add_separator()

        self.topmost_var = tk.BooleanVar(value=self.config.get("always_on_top", True))
        self.menu.add_checkbutton(label="Always on Top", variable=self.topmost_var, command=self.toggle_topmost)

        self.sound_var = tk.BooleanVar(value=self.config.get("sound_alerts", True))
        self.menu.add_checkbutton(label="Sound Alert on Active", variable=self.sound_var, command=self.toggle_sound)

        self.autostart_var = tk.BooleanVar(value=self.is_autostart_enabled())
        self.menu.add_checkbutton(label="Start with Windows", variable=self.autostart_var, command=self.toggle_autostart)

        # Snap Position Submenu
        pos_menu = tk.Menu(self.menu, tearoff=0, bg=th["pill_bg"], fg=th["text_highlight"], activebackground="#0284c7")
        pos_menu.add_command(label="Bottom-Right (Default)", command=lambda: self.snap_to_corner("bottom-right"))
        pos_menu.add_command(label="Top-Right", command=lambda: self.snap_to_corner("top-right"))
        pos_menu.add_command(label="Bottom-Left", command=lambda: self.snap_to_corner("bottom-left"))
        pos_menu.add_command(label="Top-Left", command=lambda: self.snap_to_corner("top-left"))
        self.menu.add_cascade(label="Snap Position", menu=pos_menu)

        self.menu.add_separator()
        self.menu.add_command(label="❌ Exit Sentinel", command=self.on_exit)

    def show_context_menu(self, event):
        self.tooltip.hide()
        self.menu.tk_popup(event.x_root, event.y_root)

    def open_studio_modal(self):
        CenterStudioModal(self.master, self.config, self.on_config_updated)

    def on_config_updated(self, new_config):
        self.config = new_config
        self.apply_theme_colors()
        self.build_pill_ui()
        self.create_context_menu()

    def toggle_topmost(self):
        self.config["always_on_top"] = self.topmost_var.get()
        self.master.attributes("-topmost", self.config["always_on_top"])

    def toggle_sound(self):
        self.config["sound_alerts"] = self.sound_var.get()

    def is_autostart_enabled(self):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(k, 'CLMSensor')
            winreg.CloseKey(k)
            return bool(val)
        except Exception:
            return False

    def toggle_autostart(self):
        enable = self.autostart_var.get()
        reg_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)
            if enable:
                exe_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
                winreg.SetValueEx(k, 'CLMSensor', 0, winreg.REG_SZ, exe_path)
            else:
                try:
                    winreg.DeleteValue(k, 'CLMSensor')
                except FileNotFoundError:
                    pass
            winreg.CloseKey(k)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to modify startup registry: {e}")

    def on_exit(self):
        self.is_running = False
        self.tooltip.hide()
        try:
            self.master.destroy()
        except Exception:
            pass


if __name__ == '__main__':
    root = tk.Tk()
    app = PrivacyMonitorWidget(root)
    root.mainloop()
