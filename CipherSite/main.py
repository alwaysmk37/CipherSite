import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import requests
import os
import pandas as pd
import matplotlib.pyplot as plt
from PIL import Image, ImageTk
import threading

# VirusTotal API Key (Replace with your API key)
VIRUSTOTAL_API_KEY = "d2c71241a8df7c885795f0386379ec0b74d0a33c5011d63d0c5c28d6a5f6e5cb"


# Function to scan URL
def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Enter a URL")
        return

    scan_btn.config(state=tk.DISABLED)
    progress_var.set(10)

    def perform_scan():
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        params = {"url": url}

        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            progress_var.set(50)
            scan_results = fetch_scan_results(scan_id)
            progress_var.set(100)

            update_summary(url, scan_results)
            show_full_report(url, scan_results)
            generate_donut_chart(scan_results)
        else:
            messagebox.showerror("Error", f"Scan Failed: {response.text}")

        scan_btn.config(state=tk.NORMAL)

    threading.Thread(target=perform_scan, daemon=True).start()


# Function to fetch scan results
def fetch_scan_results(scan_id):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)

    if response.status_code == 200:
        results = response.json()["data"]["attributes"]["results"]
        return [(vendor, "Clean" if data["category"] == "harmless" else "Malicious") for vendor, data in
                results.items()]
    else:
        messagebox.showerror("Error", "Failed to fetch scan results.")
        return []


# Function to update summary box
def update_summary(url, scan_results):
    malicious_count = sum(1 for _, verdict in scan_results if verdict == "Malicious")
    status = "No security vendors flagged this URL as malicious" if malicious_count == 0 else f"{malicious_count} security vendors flagged this URL"
    summary_text.set(f"Last Scan: {url}\nStatus: {status}")


# Function to show full scan report
def show_full_report(url, scan_results):
    report_window = tk.Toplevel(root)
    report_window.title("Full Scan Report")
    report_window.geometry("900x500")

    tk.Label(report_window, text=f"Full Report for: {url}", font=("Consolas", 12, "bold")).pack()

    tree = ttk.Treeview(report_window, columns=("Vendor", "Verdict"), show="headings")
    tree.heading("Vendor", text="Security Vendor")
    tree.heading("Verdict", text="Verdict")

    for vendor, verdict in scan_results:
        color = "green" if verdict == "Clean" else "red"
        tree.insert("", tk.END, values=(vendor, verdict), tags=(color,))

    tree.tag_configure("green", foreground="green")
    tree.tag_configure("red", foreground="red")
    tree.pack(expand=True, fill="both")

    export_btn = tk.Button(report_window, text="Export Report", command=lambda: export_report(url, scan_results),
                           bg="black", fg="white", font=("Consolas", 12, "bold"))
    export_btn.pack()


# Function to export report
def export_report(url, scan_results):
    filename = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[["CSV files", ".csv"], ["All Files", ".*"]])
    if filename:
        df = pd.DataFrame(scan_results, columns=["Security Vendor", "Verdict"])
        df.to_csv(filename, index=False)
        messagebox.showinfo("Success", "Report exported successfully!")


# Function to generate donut chart
def generate_donut_chart(scan_results):
    labels = ["Clean", "Malicious"]
    clean_count = sum(1 for _, verdict in scan_results if verdict == "Clean")
    malicious_count = len(scan_results) - clean_count
    sizes = [clean_count, malicious_count]
    colors = ["green", "red"]

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90, colors=colors, wedgeprops={"edgecolor": "black"})
    plt.gca().add_artist(plt.Circle((0, 0), 0.6, color='white'))  # Donut hole
    plt.title("Scan Results")
    plt.show()


# Function to set background image
def set_background(window):
    bg_image = Image.open("cyberpunk_background.jpg")  # Replace with your background image
    bg_image = bg_image.resize((600, 500), Image.LANCZOS)
    bg_photo = ImageTk.PhotoImage(bg_image)
    bg_label = tk.Label(window, image=bg_photo)
    bg_label.image = bg_photo
    bg_label.place(relwidth=1, relheight=1)


# Tkinter GUI Setup
root = tk.Tk()
root.title("CipherSite - Cyberpunk URL Scanner")
root.geometry("600x500")
set_background(root)

# Main Frame
frame = tk.Frame(root, bg="black", padx=10, pady=10, relief="ridge", bd=5)
frame.place(relx=0.5, rely=0.5, anchor="center")

# Project Name Inside Box
tk.Label(frame, text="CipherSite", fg="cyan", bg="black", font=("Consolas", 16, "bold")).pack()

# URL Entry
tk.Label(frame, text="Enter URL:", fg="cyan", bg="black", font=("Consolas", 12, "bold")).pack()
url_entry = tk.Entry(frame, width=40, font=("Consolas", 12))
url_entry.pack()

# Scan Button
scan_btn = tk.Button(frame, text="Scan URL", command=scan_url, bg="black", fg="white", font=("Consolas", 12, "bold"))
scan_btn.pack()

# Progress Bar
progress_var = tk.IntVar()
progress = ttk.Progressbar(frame, variable=progress_var, maximum=100, length=200)
progress.pack()

# Summary Box
summary_text = tk.StringVar()
summary_text.set("Last Scan: N/A\nStatus: N/A")
summary_label = tk.Label(frame, textvariable=summary_text, fg="white", bg="black", font=("Consolas", 10))
summary_label.pack()

root.mainloop()