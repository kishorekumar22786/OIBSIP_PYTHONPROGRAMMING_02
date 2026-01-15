import tkinter as tk
import string
import random

def generate_password():
    try:
        length = int(length_entry.get())

        if length < 4:
            result_label.config(text="Length must be e 4")
            return

        pool = ""

        if upper_var.get():
            pool += string.ascii_uppercase
        if lower_var.get():
            pool += string.ascii_lowercase
        if digit_var.get():
            pool += string.digits
        if symbol_var.get():
            pool += string.punctuation

        if not pool:
            result_label.config(text="Select at least one option!")
            return

        password = "".join(random.choice(pool) for _ in range(length))

        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
        result_label.config(text="Password generated!")

    except ValueError:
        result_label.config(text="Enter a valid number")

def copy_password():
    pwd = password_entry.get()
    if pwd:
        root.clipboard_clear()
        root.clipboard_append(pwd)
        result_label.config(text="Copied to clipboard!")
    else:
        result_label.config(text="No password to copy!")

root = tk.Tk()
root.title("Password Generator")
root.geometry("380x320")
root.resizable(False, False)

tk.Label(root, text="PASSWORD GENERATOR", font=("Arial", 14, "bold")).pack(pady=10)


tk.Label(root, text="Password Length:").pack()
length_entry = tk.Entry(root, width=10)
length_entry.pack()


upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
digit_var = tk.BooleanVar(value=True)
symbol_var = tk.BooleanVar(value=True)

tk.Checkbutton(root, text="Include Uppercase (A-Z)", variable=upper_var).pack(anchor="w", padx=40)
tk.Checkbutton(root, text="Include Lowercase (a-z)", variable=lower_var).pack(anchor="w", padx=40)
tk.Checkbutton(root, text="Include Digits (0-9)", variable=digit_var).pack(anchor="w", padx=40)
tk.Checkbutton(root, text="Include Symbols (!@#$...)", variable=symbol_var).pack(anchor="w", padx=40)


tk.Button(root, text="Generate Password", command=generate_password).pack(pady=10)


password_entry = tk.Entry(root, width=35)
password_entry.pack()


tk.Button(root, text="Copy", command=copy_password).pack(pady=5)

result_label = tk.Label(root, text="", fg="blue")
result_label.pack(pady=5)

root.mainloop()
