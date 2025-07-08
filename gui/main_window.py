import tkinter as tk
from tkinter import ttk, scrolledtext, Toplevel, messagebox, filedialog
import time, json, threading, os
from config import SETTINGS
from tests.performance.speed_test import run_speed_test
from scanner.port_scanner import run_port_scan
from scanner.ipv6_checker import check_ipv6
from scanner.dns_tester import run_all_dns_tests
from analyzer.predictor import analyze_results
from analyzer.database import save_result
from utils.network_status import get_status_summary
from security.security_tester import run_security_tests

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("ISP Tester Pro")
        self.root.geometry("800x600")

        self.create_menu()

        # Title
        title = ttk.Label(root, text="ISP Tester Pro", font=("Helvetica", 20, "bold"))
        title.pack(pady=10)

        # Status Bar
        self.status_label = ttk.Label(root, text=self.get_network_status(), relief="sunken", anchor="w")
        self.status_label.pack(fill="x", side="bottom")

        # Buttons
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Speed Test", command=lambda: self.run_test_window("speed")).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Port Scan", command=lambda: self.run_test_window("ports")).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="IPv6 Check", command=lambda: self.run_test_window("ipv6")).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="DNS Test", command=lambda: self.run_test_window("dns")).grid(row=0, column=3, padx=5)
        ttk.Button(button_frame, text="Security Test", command=lambda: self.run_test_window("security")).grid(row=0, column=4, padx=5)
        ttk.Button(button_frame, text="Run All Tests", command=self.run_all_tests_window).grid(row=0, column=5, padx=5)
        ttk.Button(button_frame, text="Smart Analysis", command=self.run_analysis).grid(row=0, column=6, padx=5)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Settings", command=self.open_settings_window)
        filemenu.add_command(label="Open Report", command=self.open_old_report)
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        thememenu = tk.Menu(menubar, tearoff=0)
        thememenu.add_command(label="Light Theme", command=self.set_light_theme)
        thememenu.add_command(label="Dark Theme", command=self.set_dark_theme)
        menubar.add_cascade(label="Appearance", menu=thememenu)

        self.root.config(menu=menubar)

    def set_dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2e2e2e")
        style.configure("TLabel", background="#2e2e2e", foreground="white")
        style.configure("TButton", background="#444", foreground="white")

    def set_light_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

    def get_network_status(self):
        status = get_status_summary()
        return f"🌐 Status: Internet={status['internet']} | IPv6={'Enabled' if status['ipv6'] else 'Disabled'} | DNS Hijack={'⚠️' if status['dns_hijack'] else 'Safe'}"

    def open_old_report(self):
        filepath = filedialog.askopenfilename(filetypes=[("Log Files", "*.log")])
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            win = Toplevel(self.root)
            win.title("Previous Report")
            win.geometry("600x400")
            text_area = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
            text_area.insert("1.0", content)
            text_area.pack(expand=True, fill='both')

    def run_analysis(self):
        win = Toplevel(self.root)
        win.title("Smart Network Analysis")
        win.geometry("600x400")

        log_area = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        log_area.pack(expand=True, fill='both', padx=10, pady=10)

        fake_results = {
            "speed": {"download": 35, "upload": 4, "latency": 150},
            "ports": {"open": 28, "closed": 100},
            "dns": {"working": 3, "failed": 2},
            "ipv6": {"supported": False}
        }

        report = analyze_results(fake_results)
        log_area.insert(tk.END, report + "\n")
        log_area.see(tk.END)

        try:
            save_result(fake_results, report)
            log_area.insert(tk.END, "[✔] Result saved to database.\n")
        except Exception as e:
            log_area.insert(tk.END, f"[!] Database error: {e}\n")

    def run_test_window(self, test_type):
        win = Toplevel(self.root)
        win.title(f"Running Test: {test_type}")
        win.geometry("700x500")

        log_area = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        log_area.pack(expand=True, fill='both', padx=10, pady=10)

        def log(text):
            log_area.insert(tk.END, f"{text}\n")
            log_area.see(tk.END)
            win.update()

        def run():
            start = time.time()
            log(f"Test started: {test_type}")
            try:
                if test_type == "speed":
                    run_speed_test(log)
                elif test_type == "ports":
                    run_port_scan(log)
                elif test_type == "ipv6":
                    check_ipv6(log)
                elif test_type == "dns":
                    run_all_dns_tests(log)
                elif test_type == "security":
                    run_security_tests(log)
            except Exception as e:
                log(f"[!] Error: {e}")
            duration = time.time() - start
            log(f"Execution Time: {duration:.2f} seconds")
            timestamp = time.strftime("%Y-%m-%d_%H-%M")
            os.makedirs("reports", exist_ok=True)
            with open(f"reports/{timestamp}_{test_type}.log", "w", encoding="utf-8") as f:
                f.write(log_area.get("1.0", tk.END))

        threading.Thread(target=run).start()

    def run_all_tests_window(self):
        win = Toplevel(self.root)
        win.title("Running All Tests")
        win.geometry("700x500")

        log_area = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        log_area.pack(expand=True, fill='both', padx=10, pady=10)

        def log(text):
            log_area.insert(tk.END, f"{text}\n")
            log_area.see(tk.END)
            win.update()

        def run_all():
            start = time.time()
            log("Starting Full ISP Test...\n")
            try:
                run_speed_test(log)
                run_port_scan(log)
                check_ipv6(log)
                run_all_dns_tests(log)
                run_security_tests(log)
            except Exception as e:
                log(f"[!] Error: {e}")
            duration = time.time() - start
            log(f"All tests completed. Total time: {duration:.2f} seconds")
            timestamp = time.strftime("%Y-%m-%d_%H-%M")
            os.makedirs("reports", exist_ok=True)
            with open(f"reports/{timestamp}_full.log", "w", encoding="utf-8") as f:
                f.write(log_area.get("1.0", tk.END))

        threading.Thread(target=run_all).start()

    def open_settings_window(self):
        win = Toplevel(self.root)
        win.title("Settings")
        win.geometry("600x400")

        with open("settings.json", "r", encoding="utf-8") as f:
            content = f.read()

        text_area = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        text_area.insert("1.0", content)
        text_area.pack(expand=True, fill="both", padx=10, pady=10)

        def save_settings():
            try:
                new_content = text_area.get("1.0", tk.END)
                json.loads(new_content)
                with open("settings.json", "w", encoding="utf-8") as f:
                    f.write(new_content)
                messagebox.showinfo("Settings", "Saved successfully.")
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Invalid settings:\n{e}")

        ttk.Button(win, text="Save", command=save_settings).pack(pady=5)

def run_gui():
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")
    app = MainWindow(root)
    root.mainloop()
