import tkinter as tk
import winreg
import math
import subprocess
import threading
import ctypes
import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32

class PrivacyMonitorWidget:
    def __init__(self, master):
        self.master = master
        
        # Frameless window
        self.master.overrideredirect(True)
        self.master.wm_attributes("-toolwindow", True)
        self.master.attributes("-topmost", True)
        
        # Transparent background
        self.color_bg = '#010101'
        self.master.attributes("-transparentcolor", self.color_bg)
        self.master.configure(bg=self.color_bg)
        
        self.width = 90
        self.height = 30
        
        # Position
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        x = screen_width - 380 
        y = screen_height - self.height - 10
        master.geometry(f"{self.width}x{self.height}+{x}+{y}")
        
        self.canvas = tk.Canvas(master, width=self.width, height=self.height, 
                                bg=self.color_bg, highlightthickness=0)
        self.canvas.pack()
        
        # --- UI Drawing ---
        self.round_rectangle(2, 2, self.width-2, self.height-2, radius=13, fill='#151515', outline='#444444', width=1)
        self.round_rectangle(3, 3, self.width-3, self.height-3, radius=12, fill='#252525', outline='', width=0)
        
        self.canvas.create_line(31, 8, 31, 26, fill="#3a3a3a", width=1)
        self.canvas.create_line(59, 8, 59, 26, fill="#3a3a3a", width=1)
        
        # Rims
        self.canvas.create_oval(13, 6, 21, 14, fill='#0a0a0a', outline='#111111')
        self.canvas.create_oval(41, 6, 49, 14, fill='#0a0a0a', outline='#111111')
        self.canvas.create_oval(69, 6, 77, 14, fill='#0a0a0a', outline='#111111')
        
        # Glow Lights (initially greyed out)
        self.color_grey = '#222222'
        self.light_cam = self.canvas.create_oval(14, 7, 20, 13, fill=self.color_grey, outline='')
        self.light_mic = self.canvas.create_oval(42, 7, 48, 13, fill=self.color_grey, outline='')
        self.light_loc = self.canvas.create_oval(70, 7, 76, 13, fill=self.color_grey, outline='')
        
        # Text
        tiny_font = ("Segoe UI", 6)
        self.canvas.create_text(17, 23, text="CAM", fill="#999999", font=tiny_font)
        self.canvas.create_text(45, 23, text="MIC", fill="#999999", font=tiny_font)
        self.canvas.create_text(73, 23, text="LOC", fill="#999999", font=tiny_font)
        
        self.master.bind("<FocusIn>", self.force_topmost)
        self.canvas.bind("<Enter>", self.force_topmost)
        self.canvas.bind("<ButtonPress-1>", self.start_move)
        self.canvas.bind("<ButtonRelease-1>", self.stop_move)
        self.canvas.bind("<B1-Motion>", self.do_move)
        self.canvas.bind("<Button-3>", lambda e: master.destroy())
        
        # State
        self.cam_active = False
        self.mic_active = False
        self.loc_active = False
        
        self.cam_enabled = True
        self.mic_enabled = True
        self.loc_enabled = True
        
        self.cam_hw_enabled = True  # Tracks hardware kill-switch (Fn keys)
        
        self.flicker_state = False
        
        # Start loops
        self.keep_topmost_loop()
        self.hardware_check_loop()
        self.system_check_loop()
        self.animation_loop()

    def keep_topmost_loop(self):
        try:
            import ctypes
            # Get the absolute root HWND
            hwnd = ctypes.windll.user32.GetParent(self.master.winfo_id())
            if not hwnd:
                hwnd = self.master.winfo_id()
                
            # HWND_TOPMOST = -1
            # SWP_NOSIZE = 1 | SWP_NOMOVE = 2 | SWP_NOACTIVATE = 16
            ctypes.windll.user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 1 | 2 | 16)
            self.master.attributes('-topmost', True)
        except Exception:
            pass
        self.master.after(500, self.keep_topmost_loop)

    def round_rectangle(self, x1, y1, x2, y2, radius=25, **kwargs):
        points = [x1+radius, y1, x1+radius, y1, x2-radius, y1, x2-radius, y1, x2, y1, x2, y1+radius, x2, y1+radius, x2, y2-radius, x2, y2-radius, x2, y2, x2-radius, y2, x2-radius, y2, x1+radius, y2, x1+radius, y2, x1, y2, x1, y2-radius, x1, y2-radius, x1, y1+radius, x1, y1+radius, x1, y1]
        return self.canvas.create_polygon(points, **kwargs, smooth=True)

    def force_topmost(self, event=None):
        self.master.attributes('-topmost', True)

    def start_move(self, event):
        self.x = event.x; self.y = event.y
        self.force_topmost()

    def stop_move(self, event):
        self.x = None; self.y = None
        self.force_topmost()

    def do_move(self, event):
        x = self.master.winfo_x() + (event.x - self.x)
        y = self.master.winfo_y() + (event.y - self.y)
        self.master.geometry(f"+{x}+{y}")
        self.force_topmost()

    def check_in_use(self, capability):
        in_use = False
        base_key_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\' + capability
        try:
            base_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key_path)
        except FileNotFoundError:
            return False

        def check_subkeys(key):
            nonlocal in_use
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    i += 1
                    if subkey_name == 'NonPackaged':
                        try:
                            np_key = winreg.OpenKey(key, subkey_name)
                            check_subkeys(np_key)
                            winreg.CloseKey(np_key)
                        except OSError:
                            pass
                        continue
                    
                    try:
                        app_key = winreg.OpenKey(key, subkey_name)
                        try:
                            start_time, _ = winreg.QueryValueEx(app_key, 'LastUsedTimeStart')
                            stop_time, _ = winreg.QueryValueEx(app_key, 'LastUsedTimeStop')
                            # If stop_time is 0, or start_time is greater than stop_time, it's currently in use
                            if (stop_time == 0 and start_time != 0) or (start_time > stop_time):
                                in_use = True
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(app_key)
                    except OSError:
                        pass
                except OSError:
                    break

        check_subkeys(base_key)
        winreg.CloseKey(base_key)
        return in_use

    def check_permission_state(self, capability):
        # Checks if permission is denied globally or per-user
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\' + capability),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\' + capability),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\' + capability + r'\NonPackaged')
        ]
        for root, path in paths:
            try:
                key = winreg.OpenKey(root, path)
                val, _ = winreg.QueryValueEx(key, 'Value')
                winreg.CloseKey(key)
                if val == 'Deny':
                    return False
            except OSError:
                pass
        return True

    def hardware_check_loop(self):
        # Runs a background thread to check if camera is hardware-disabled (Fn + F10)
        def run_check():
            try:
                # 0x08000000 = CREATE_NO_WINDOW so it doesn't flash cmd
                res = subprocess.run(['powershell', '-Command', 'Get-PnpDevice -Class Camera -Status OK'], 
                                     capture_output=True, creationflags=0x08000000)
                # returncode 0 means at least one camera is Present and OK
                self.cam_hw_enabled = (res.returncode == 0)
            except Exception:
                pass
                
        threading.Thread(target=run_check, daemon=True).start()
        
        # Check hardware every 4 seconds
        self.master.after(4000, self.hardware_check_loop)

    def system_check_loop(self):
        # Check permissions (Allowed vs Denied) and Hardware Switch
        self.cam_enabled = self.check_permission_state('webcam') and self.cam_hw_enabled
        self.mic_enabled = self.check_permission_state('microphone')
        self.loc_enabled = self.check_permission_state('location')
        
        # Check actual active usage
        self.cam_active = self.check_in_use('webcam')
        self.mic_active = self.check_in_use('microphone')
        self.loc_active = self.check_in_use('location')
        
        # Check every 2 seconds
        self.master.after(2000, self.system_check_loop)

    def animation_loop(self):
        self.flicker_state = not self.flicker_state
        
        # CAM Logic: Active -> Red Flicker, Enabled -> Green, Disabled -> Grey
        if self.cam_active:
            color = '#ff0000' if self.flicker_state else '#660000'
            self.canvas.itemconfigure(self.light_cam, fill=color)
        elif self.cam_enabled:
            self.canvas.itemconfigure(self.light_cam, fill='#00ff00')
        else:
            self.canvas.itemconfigure(self.light_cam, fill='#222222')
            
        # MIC Logic: Active -> Yellow Flicker, Enabled -> Green, Disabled -> Grey
        if self.mic_active:
            color = '#ffcc00' if self.flicker_state else '#665500'
            self.canvas.itemconfigure(self.light_mic, fill=color)
        elif self.mic_enabled:
            self.canvas.itemconfigure(self.light_mic, fill='#00ff00')
        else:
            self.canvas.itemconfigure(self.light_mic, fill='#222222')
            
        # LOC Logic: Active -> Red Flicker, Enabled -> Green, Disabled -> Grey
        if self.loc_active:
            color = '#ff0000' if self.flicker_state else '#660000'
            self.canvas.itemconfigure(self.light_loc, fill=color)
        elif self.loc_enabled:
            self.canvas.itemconfigure(self.light_loc, fill='#00ff00')
        else:
            self.canvas.itemconfigure(self.light_loc, fill='#222222')
            
        # Flicker speed: 400ms
        self.master.after(400, self.animation_loop)

if __name__ == '__main__':
    root = tk.Tk()
    app = PrivacyMonitorWidget(root)
    root.mainloop()
