import tkinter as tk
from tkinter import ttk
import secrets
import string
import hashlib

AMBIGUOUS = set("Il1O0")

# ---------------- PASSWORD LOGIC ---------------- #
def build_charset(upper, lower, digits, symbols, avoid_ambig):
    charset = ""
    if upper:  charset += string.ascii_uppercase
    if lower:  charset += string.ascii_lowercase
    if digits: charset += string.digits
    if symbols: charset += "!@#$%^&*()-_=+[]{};:,.<>/?"
    if avoid_ambig:
        charset = "".join(ch for ch in charset if ch not in AMBIGUOUS)
    return charset

def generate_password(length, charset):
    if not charset:
        return "❌ Select at least one category!"
    return "".join(secrets.choice(charset) for _ in range(length))

def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)

# ---------------- HASHING ---------------- #
def hash_password(password):
    """Return the SHA-256 hash of the password."""
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------- DARK MODE ---------------- #
def apply_theme():
    bg = "#1e1e1e" if dark_mode.get() else "#f0f0f0"
    fg = "white" if dark_mode.get() else "black"
    entry_bg = "#2a2a2a" if dark_mode.get() else "white"
    slider_trough = "#2a2a2a" if dark_mode.get() else "#d0d0d0"
    slider_bg = "#444444" if dark_mode.get() else "#c0c0c0"
    btn_bg = "#5555ff" if dark_mode.get() else "#2196f3"
    btn_fg = "white"
    copy_btn_bg = "#4caf50" if dark_mode.get() else "#4caf50"

    root.configure(bg=bg)
    main.configure(bg=bg)

    for widget in main.winfo_children():
        cls = widget.winfo_class()
        if cls in ["TLabel", "Label"]:
            widget.configure(bg=bg, fg=fg)
        elif cls == "TCheckbutton":
            widget.configure(bg=bg, fg=fg, selectcolor=bg)
        elif cls == "Entry":
            widget.configure(bg=entry_bg, fg=fg, insertbackground=fg)
        elif cls == "Button":
            if widget not in [theme_button, generate_button, copy_button]:
                widget.configure(bg=btn_bg, fg=btn_fg)

    theme_button.configure(bg="#9c27b0", fg="white")
    generate_button.configure(bg=btn_bg, fg=btn_fg, activebackground="#6666ff" if dark_mode.get() else "#1976d2")
    copy_button.configure(bg=copy_btn_bg, fg="white", activebackground="#5cbf60")
    theme_button.configure(text="☀ Light Mode" if dark_mode.get() else "🌙 Dark Mode")

def toggle_theme():
    dark_mode.set(not dark_mode.get())
    apply_theme()

# ---------------- EVENT HANDLERS ---------------- #
def update_hash_display():
    if show_hash_var.get():
        hashed = hash_password(password_var.get())
        hash_label.config(text=f"SHA-256 Hash: {hashed}")
    else:
        hash_label.config(text="")

def on_generate():
    length = length_var.get()
    charset = build_charset(
        upper_var.get(), lower_var.get(), digits_var.get(),
        symbols_var.get(), ambig_var.get()
    )
    pw = generate_password(length, charset)
    password_var.set(pw)
    update_hash_display()

def on_copy():
    copy_to_clipboard(password_var.get())
    copy_label.config(text="Copied!", fg="green")
    root.after(1500, lambda: copy_label.config(text="", fg="white" if dark_mode.get() else "black"))

def update_length_label(event):
    length_value_label.config(text=str(int(length_var.get())))

# ---------------- GUI SETUP ---------------- #
root = tk.Tk()
root.title("Password Generator with Hash")
root.geometry("520x460")
root.resizable(False, False)
style = ttk.Style()

main = tk.Frame(root, padx=25, pady=25)
main.pack(fill="both", expand=True)

# Password Entry
password_var = tk.StringVar()
password_entry = tk.Entry(main, textvariable=password_var, font=("Consolas", 14, "bold"),
                          width=36, justify="center", relief="flat", bd=5)
password_entry.grid(row=0, column=0, columnspan=4, pady=(0,10))

copy_button = tk.Button(main, text="Copy", command=on_copy, font=("Segoe UI", 10, "bold"),
                        relief="flat", bd=0, padx=10)
copy_button.grid(row=0, column=4, padx=5)

copy_label = tk.Label(main, text="", font=("Segoe UI", 9))
copy_label.grid(row=1, column=0, columnspan=5, pady=(0,10))

# Password Length Slider
tk.Label(main, text="Length:").grid(row=2, column=0, sticky="w")
length_var = tk.IntVar(value=16)
length_slider = ttk.Scale(main, from_=6, to=64, orient="horizontal", variable=length_var, command=update_length_label)
length_slider.grid(row=2, column=1, columnspan=3, sticky="ew", padx=(5,0))
length_value_label = tk.Label(main, text=str(length_var.get()), width=3)
length_value_label.grid(row=2, column=4, sticky="w")

# Character Options
upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)
ambig_var = tk.BooleanVar(value=False)

opts = [
    ("Uppercase (A–Z)", upper_var),
    ("Lowercase (a–z)", lower_var),
    ("Digits (0–9)", digits_var),
    ("Symbols (!@#$)", symbols_var),
    ("Avoid ambiguous (Il1O0)", ambig_var),
]

row = 3
for label, var in opts:
    tk.Checkbutton(main, text=label, variable=var, anchor="w").grid(row=row, column=0, columnspan=5, sticky="w", pady=2)
    row += 1

# Show hash checkbox
show_hash_var = tk.BooleanVar(value=False)
tk.Checkbutton(main, text="Show SHA-256 Hash", variable=show_hash_var,
               command=update_hash_display, anchor="w").grid(row=row, column=0, columnspan=5, sticky="w", pady=2)
row += 1

# Hash label
hash_label = tk.Label(main, text="", font=("Consolas", 10), wraplength=480, justify="left")
hash_label.grid(row=row, column=0, columnspan=5, pady=(5,0), sticky="w")
row += 1

# Generate Button
generate_button = tk.Button(main, text="Generate Password", command=on_generate,
                            relief="flat", bd=0, padx=10, pady=5)
generate_button.grid(row=row, column=0, columnspan=5, pady=15, sticky="ew")
row += 1

# Dark Mode Toggle
dark_mode = tk.BooleanVar(value=False)
theme_button = tk.Button(main, text="🌙 Dark Mode", command=toggle_theme,
                         relief="flat", bd=0, padx=10, pady=5)
theme_button.grid(row=row, column=0, columnspan=5, sticky="ew")

root.bind("<Control-c>", lambda e: on_copy())

apply_theme()
on_generate()
root.mainloop()
