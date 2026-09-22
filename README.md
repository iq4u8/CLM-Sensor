<div align="center">

# 🛡️ CLM Sensor
### Real-Time Hardware & OS Privacy Sentinel for Windows 10 & 11

<br />

![CLM Sensor Animated Banner](assets/sensor-banner.svg)

<br />

[![Platform: Windows 10 & 11](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078d4.svg?style=for-the-badge&logo=windows)](https://microsoft.com/windows)
[![Language: Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab.svg?style=for-the-badge&logo=python)](https://python.org)
[![Privacy: 100% Air-Gapped](https://img.shields.io/badge/Network-0%20KB%20%28100%25%20Offline%29-10b981.svg?style=for-the-badge)]()
[![Hardware: Kill-Switch Sensing](https://img.shields.io/badge/Hardware-Fn%20Key%20PnP%20Audit-f59e0b.svg?style=for-the-badge)]()
[![GUI: Frameless Win32 HUD](https://img.shields.io/badge/GUI-Frameless%20Win32%20HUD-ef4444.svg?style=for-the-badge)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

<br />

> **An ultra-lightweight, frameless, and transparent always-on-top desktop sentinel that instantly alerts you whenever any application accesses your Camera, Microphone, or Location — with physical hardware kill-switch sensing.**

[Overview](#-executive-overview) • [How It Works](#-how-it-works-under-the-hood) • [Pipeline](#-detection-pipeline-architecture) • [LED Status Matrix](#-visual-led-indicator-matrix) • [Quickstart](#-installation--quickstart) • [Author](#-author)

---

</div>

## 📌 Executive Overview

Modern operating systems, background meeting apps (Teams, Zoom, Discord), rogue browser extensions, and invasive analytics software frequently access webcams, microphones, and GPS coordinates without explicit user awareness. While some premium laptops feature physical hardware LEDs, budget machines and USB peripherals often lack reliable indicators.

**CLM Sensor** solves this by establishing a continuous, non-invasive surveillance sentinel right above your Windows taskbar:

* **Always-On-Top Mini HUD Pill**: Floats silently on your desktop, taking less than 15 MB of RAM and 0% CPU.
* **Instant Visual Alerts**: Real-time LED pulses whenever Camera (🔴 Red Alert), Microphone (🟡 Audio Alert), or Location (🔴 Coordinate Alert) are actively tapped.
* **Fn Kill-Key Aware**: Detects whether your laptop's physical webcam kill-switch (e.g. `Fn + F10`) or Windows global privacy toggle has disabled the sensor at the hardware driver level.
* **100% Air-Gapped**: Zero network permissions, zero telemetry, zero cloud calls. All state audits happen locally in RAM.

---

## ⚡ Detection Pipeline Architecture

The sentinel connects directly into Windows kernel-level tracking systems without installing invasive kernel drivers or rootkits:

<br />

![CLM Sensor Detection Pipeline](assets/sensor-architecture.svg)

<br />

---

## 🔬 How It Works Under the Hood

### 1. 🔑 Windows `CapabilityAccessManager` (ConsentStore) Polling
Windows 10 and 11 track every device access event in the system registry under:
```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\
  ├── webcam/
  ├── microphone/
  └── location/
```
Inside each capability key, Windows creates records for both modern UWP store apps and traditional Win32 desktop executables (`NonPackaged/`).

Each subkey contains two critical 64-bit timestamps:
* `LastUsedTimeStart`: Windows FILETIME timestamp when the application began recording.
* `LastUsedTimeStop`: Timestamp when the application ceased recording (set to `0` while actively capturing!).

**The Mathematical Detection Logic:**
```python
# If stop_time is 0 while start_time > 0, or start_time is greater than stop_time:
in_use = (stop_time == 0 and start_time != 0) or (start_time > stop_time)
```
Whenever this condition evaluates to `True`, the respective sensor is **actively streaming audio, video, or location coordinates right now**!

---

### 2. ⚡ Asynchronous Hardware Kill-Switch Detection (Fn + F10)
Modern laptops provide hardware toggle switches or keyboard hotkeys (like `Fn + F10`) that physically cut power to the camera sensor. 

To detect this without freezing the Tkinter main UI event loop, CLM Sensor spawns a daemon background thread every 4 seconds running:
```powershell
Get-PnpDevice -Class Camera -Status OK
```
* **Stealth Process Execution**: Spawned with `creationflags=0x08000000` (`CREATE_NO_WINDOW`), ensuring no black command prompt window ever flashes on your screen.
* **Dynamic State Sync**: If the camera driver is detached or in an error state, CLM Sensor immediately downgrades the `CAM` indicator to disabled grey (`#222222`).

---

### 3. 🪟 True Frameless & Always-on-Top Win32 HUD
Rather than standard OS window borders, CLM Sensor utilizes direct Win32 API calls via Python `ctypes`:
* **Native HWND Pinning**:
  ```python
  # HWND_TOPMOST = -1
  # SWP_NOSIZE = 1 | SWP_NOMOVE = 2 | SWP_NOACTIVATE = 16
  ctypes.windll.user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 1 | 2 | 16)
  ```
* **Chroma-Key Transparency**: The Tkinter canvas uses `-transparentcolor` with a matte black `#010101` mask to produce smooth anti-aliased curved corners (`radius=13`).
* **Interactive Dragging**: Left-click and drag anywhere on the pill to reposition it across multiple monitors; right-click anywhere to instantly exit.

---

## 🚦 Visual LED Indicator Matrix

| Sensor | State | Color & Animation | Description |
|:---:|:---:|:---:|---|
| **CAM** | **Idle & Armed** | 🟢 **Solid Emerald Green** (`#00ff00`) | Camera driver is enabled, hardware switch is ON, and permissions are granted. |
| **CAM** | **Active Alert** | 🔴 **Flickering Crimson Red** (`#ff0000`) | **RECORDING DETECTED!** An app is currently streaming frames from your webcam. |
| **CAM** | **Disabled** | ⚫ **Matte Dark Grey** (`#222222`) | Camera is hardware-disabled (Fn kill-key) or blocked in Windows Privacy Settings. |
| **MIC** | **Idle & Armed** | 🟢 **Solid Emerald Green** (`#00ff00`) | Microphone is plugged in, permitted, and standing by. |
| **MIC** | **Active Audio** | 🟡 **Flickering Amber Yellow** (`#ffcc00`) | **AUDIO STREAM ACTIVE!** An app is actively capturing microphone input. |
| **MIC** | **Disabled** | ⚫ **Matte Dark Grey** (`#222222`) | Microphone permission denied globally or device unplugged. |
| **LOC** | **Idle & Armed** | 🟢 **Solid Emerald Green** (`#00ff00`) | Windows Location Services permitted and available. |
| **LOC** | **Active Query** | 🔴 **Flickering Crimson Red** (`#ff0000`) | **GEO-LOCATION QUERY!** An application is querying GPS/WiFi positioning. |
| **LOC** | **Disabled** | ⚫ **Matte Dark Grey** (`#222222`) | Location Services toggled OFF in Windows Settings. |

---

## 💻 Installation & Quickstart

### Prerequisites
* **Operating System**: Windows 10 or Windows 11 (64-bit recommended)
* **Python**: Python 3.10 or newer (uses built-in standard libraries: `tkinter`, `winreg`, `ctypes`, `subprocess`, `threading`)

### Option A: Run from Source
```bash
# Clone the repository
git clone https://github.com/iq4u8/CLM-Sensor.git
cd CLM-Sensor

# Launch the sentinel
python sensor.py
```

### Option B: Compile to Standalone Binary
To compile CLM Sensor into an ultra-fast standalone `.exe` without console windows:
```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --icon=icon.ico sensor.py
```
The compiled executable will be generated inside `dist/sensor.exe`.

---

## 🎮 Desktop Controls & Shortcuts

| Action | Control | Result |
|---|---|---|
| **Reposition HUD** | `Left-Click + Drag` | Move the floating pill to any position on any monitor. |
| **Exit Sentinel** | `Right-Click` | Instantly destroys the widget and releases memory. |
| **Hover & Re-Pin** | `Mouse Hover` | Forces `HWND_TOPMOST` z-index above full-screen applications. |

---

## 📂 Repository Structure

```
CLM-Sensor/
├── sensor.py                 # Core Python Sentinel: WinReg hooks, Tkinter HUD & PnP threads
├── icon.ico                  # Application high-res multi-tier Windows icon
├── README.md                 # Visual Architecture & Documentation
└── assets/
    ├── sensor-banner.svg     # Animated vector SVG hero banner with glowing HUD & radar
    └── sensor-architecture.svg # Animated architecture pipeline with streaming data flow
```

---

## 👨‍💻 Author

**Priyanshu Pandey (IQ4U8)**
* **Specialization**: Windows System Architecture, Win32 API Utilities, FinTech & Zero-Knowledge Systems
* **GitHub**: [@iq4u8](https://github.com/iq4u8)
* **Portfolio**: [Priyanshu Pandey Portfolio](https://github.com/iq4u8)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
