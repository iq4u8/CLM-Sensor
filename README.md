# 🛡️ CLM Sensor

<div align="center">
  <img src="icon.ico" width="100" alt="App Icon">
</div>

> **Developed by:** Priyanshu Pandey

## 📌 Overview
A lightweight, real-time privacy monitoring utility for Windows OS. This application provides an unobtrusive, frameless, and transparent always-on-top widget that visually alerts you the moment any application attempts to access your **Camera**, **Microphone**, or **Location**.

## 💻 Technical Architecture
*   **Language:** Python 3
*   **UI Framework:** Custom Frameless Tkinter GUI (`ctypes` for Win32 API integration)
*   **System Integration:** `winreg` (Live Registry Polling) & `subprocess` (PowerShell device queries)
*   **Packaging:** PyInstaller

## ⚙️ Core Engineering Features
1.  **Live Registry Polling:** Constantly monitors the Windows `CapabilityAccessManager\ConsentStore` registry to detect active background or foreground sensor usage.
2.  **Hardware Kill-Switch Detection:** Implements background multithreading to execute PowerShell (`Get-PnpDevice`) and detect if the camera has been physically disabled at the hardware level (e.g., via a laptop's Fn key) without freezing the main UI thread.
3.  **Always-on-Top Widget:** Utilizes `ctypes.windll.user32` to create a sleek, draggable widget that seamlessly hovers over all other windows.
4.  **Dynamic Visual Indicators:**
    *   🟢 **Green:** Sensor is enabled and ready.
    *   ⚪ **Grey:** Sensor is disabled via hardware or system privacy settings.
    *   🔴/🟡 **Flickering:** Sensor is **ACTIVELY IN USE** (Alerting the user to potential spying/recording).

## 🚀 Future Roadmap
*   **Bluetooth Connectivity Detection:** Monitor active BT connections and alert on unauthorized pairing.
*   **Battery Saver Integration:** Optimize background polling threads to pause or slow down when the system switches to battery power.
*   **Low RAM Consumption Mode:** Deep optimization of the memory footprint for background threads.
