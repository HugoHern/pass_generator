import tkinter as tk
from tkinter import ttk
import secrets
import string

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

# ---------------- DARK MODE ---------------- #

def apply_theme():
    if dark_mode.get():
        style.theme_use("clam")
        root.configure(bg="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("TCheckbutton", background="#1e1e1e", foreground="white")
        style.configure("TButton", background="#3b3b3b", foreground="white")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("Horizontal.TScale", troughcolor="#2d2d2d", background="#3b3b3b")
        password_entry.configure(background="#2d2d2d", foreground="white", insertbackground="white")
        theme_button.configure(text="☀ Light Mode")
    else:
        style.theme_use("default")
        root.configure(bg="SystemButtonFace")
        password_entry.configure(background="white", foreground="black", insertbackground="black")
        theme_button.configure(text="🌙 Dark Mode")

def toggle_theme():
    dark_mode.set(not dark_mode.get())
    apply_theme()

# ---------------- EVENT HANDLERS ---------------- #

def on_generate():
    length = length_var.get()
    charset = build_charset(
        upper_var.get(),
        lower_var.get(),
        digits_var.get(),
        symbols_var.get(),
        ambig_var.get()
    )
    pw = generate_password(length, charset)
    password_var.set(pw)

def on_copy():
    copy_to_clipboard(password_var.get())
    copy_label.config(text="Copied!", foreground="green")
    root.after(1500, lambda: copy_label.config(text="", foreground="green" if dark_mode.get() else "black"))

def update_length_label(event):
    length_value_label.config(text=str(int(length_var.get())))

# ---------------- GUI SETUP ---------------- #

root = tk.Tk()
root.title("Password Generator")
root.geometry("500x400")
root.resizable(True, True)

style = ttk.Style()

main = ttk.Frame(root, padding=20)
main.pack(fill="both", expand=True)

# Output field
password_var = tk.StringVar()
password_entry = tk.Entry(main, textvariable=password_var, font=("Courier", 14), width=32)
password_entry.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky="ew")

copy_button = ttk.Button(main, text="Copy", command=on_copy)
copy_button.grid(row=0, column=3, padx=5)

copy_label = ttk.Label(main, text="", font=("TkDefaultFont", 9))
copy_label.grid(row=1, column=0, columnspan=4, pady=(0,10))

# Length slider
ttk.Label(main, text="Length:").grid(row=2, column=0, sticky="w")
length_var = tk.IntVar(value=16)
length_slider = ttk.Scale(main, from_=6, to=64, orient="horizontal", variable=length_var, command=update_length_label)
length_slider.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(5,0))

length_value_label = ttk.Label(main, text=str(length_var.get()), width=3)
length_value_label.grid(row=2, column=3, sticky="w")

# Checkboxes
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
    ttk.Checkbutton(main, text=label, variable=var).grid(row=row, column=0, columnspan=4, sticky="w", pady=2)
    row += 1

# Generate button
generate_button = ttk.Button(main, text="Generate Password", command=on_generate)
generate_button.grid(row=row, column=0, columnspan=4, pady=15, sticky="ew")

# Dark mode toggle button
dark_mode = tk.BooleanVar(value=False)
theme_button = ttk.Button(main, text="🌙 Dark Mode", command=toggle_theme)
theme_button.grid(row=row+1, column=0, columnspan=4, sticky="ew")

# Keyboard shortcut Ctrl+C to copy
root.bind("<Control-c>", lambda e: on_copy())

# Apply initial theme and generate first password
apply_theme()
on_generate()

root.mainloop()
