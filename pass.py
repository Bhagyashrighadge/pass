import tkinter as tk
from tkinter import messagebox
import random
import string

def validate_length(length):
    # Check if the provided password length is valid
    try:
        length = int(length)
        if length <= 0:
            raise ValueError("Password length must be greater than 0.")
        return length
    except ValueError:
        raise ValueError("Please enter a valid positive number for password length.")

def generate_password():
    # Generate a random password based on user-selected criteria
    try:
        length = validate_length(length_var.get())
        use_letters = letters_var.get()
        use_numbers = numbers_var.get()
        use_symbols = symbols_var.get()

        exclude_chars = exclude_var.get()
        character_pool = ""

        if use_letters:
            character_pool += string.ascii_letters
        if use_numbers:
            character_pool += string.digits
        if use_symbols:
            character_pool += string.punctuation

        if not character_pool:
            raise ValueError("Please select at least one type of characters.")

        if exclude_chars:
            character_pool = ''.join(c for c in character_pool if c not in exclude_chars)

        if not character_pool:
            raise ValueError("All characters are excluded. Adjust exclusions.")

        password = ''.join(random.choice(character_pool) for _ in range(length))
        password_var.set(password)
    except ValueError as e:
        messagebox.showerror("Input Error", str(e))

def copy_to_clipboard():
    # Copy the generated password to clipboard
    password = password_var.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showerror("Error", "No password available to copy.")

# Set up the main application window
root = tk.Tk()
root.title("Password Generator")
root.configure(bg="black")
root.state("zoomed")  # Adjust window to full screen

# Variables to hold user inputs
length_var = tk.StringVar(value="8")
letters_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=False)
exclude_var = tk.StringVar()
password_var = tk.StringVar()

# Styling settings for widgets
label_style = {"bg": "black", "fg": "sky blue", "font": ("Arial", 12)}
entry_style = {"bg": "gray", "fg": "white", "font": ("Arial", 12)}
button_style = {"bg": "green", "fg": "black", "font": ("Arial", 12, "bold"), "activebackground": "sky blue", "activeforeground": "black"}
checkbox_style = {"bg": "black", "fg": "red", "font": ("Arial", 12)}

# Create the main frame to hold all widgets
frame = tk.Frame(root, bg="black", padx=10, pady=10)
frame.pack(fill=tk.BOTH, expand=True)

# Input for password length
tk.Label(frame, text="Password Length:", **label_style).grid(row=0, column=0, sticky="w", pady=5)
tk.Entry(frame, textvariable=length_var, **entry_style).grid(row=0, column=1, pady=5)

# Options to include different types of characters
tk.Checkbutton(frame, text="Include Letters", variable=letters_var, **checkbox_style).grid(row=1, column=0, columnspan=2, sticky="w", pady=2)
tk.Checkbutton(frame, text="Include Numbers", variable=numbers_var, **checkbox_style).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
tk.Checkbutton(frame, text="Include Symbols", variable=symbols_var, **checkbox_style).grid(row=3, column=0, columnspan=2, sticky="w", pady=2)

# Input for excluding specific characters
tk.Label(frame, text="Exclude Characters:", **label_style).grid(row=4, column=0, sticky="w", pady=5)
tk.Entry(frame, textvariable=exclude_var, **entry_style).grid(row=4, column=1, pady=5)

# Button to generate the password
btn_generate = tk.Button(frame, text="Generate Password", command=generate_password, **button_style)
btn_generate.grid(row=5, column=0, columnspan=2, pady=15)

# Display the generated password
tk.Entry(frame, textvariable=password_var, state="readonly", **entry_style).grid(row=6, column=0, columnspan=2, pady=5)

# Button to copy the password
copy_button = tk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard, **button_style)
copy_button.grid(row=7, column=0, columnspan=2, pady=10)

# Run the Tkinter main loop
root.mainloop()
