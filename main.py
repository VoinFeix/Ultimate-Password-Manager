import tkinter as tk
import time
from tkinter import messagebox
import secrets
import string
import hashlib
import os
from cryptography.fernet import Fernet
import cryptography

FILENAME = ".saved_passwords.txt"

KEYFILENAME = "key.key"
key = None
fernet = None
def encryptionInit():
    global key, fernet, KEYFILENAME
    try:
        path = '.passwd/config/file/key/'
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as err:
            print(f"[OS Makedirs Error]: {str(err)}")

        key = Fernet.generate_key()
        folderPath = path + KEYFILENAME
        fernet = Fernet(key)
        filename = ''.join(folderPath)

        with open(filename, 'wb') as f:
            f.write(key)

    except Exception as e:
        print(f"[Encryption Init Error]: {str(e)}")

encryptionInit()

def encryptFile(filename):
    global fernet
    try:
        with open(filename, 'rb') as f:
            original = f.read()
        encrypted = fernet.encrypt(original)

        with open(filename, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        print(f"[Encryption File Error]: {str(e)}")

def decryptFile(filename):
    global fernet
    try:
        with open(filename, 'rb') as f:
            encrypted = f.read()

        decrypted = fernet.decrypt(encrypted)

        with open(filename, 'wb') as f:
            f.write(decrypted)
    except Exception as e:
        print(f"[Decryption File Error]: {str(e)}")

# Define light theme color scheme
light_theme = {
    "bg": "white",
    "fg": "black",
    "button_bg": "#f0f0f0",
    "button_fg": "black",
    "entry_bg": "white",
    "entry_fg": "black",
    "text_bg": "white",
    "text_fg": "black",
    "selectcolor": "gray"
}

# Define dark theme color scheme
dark_theme = {
    "bg": "black",
    "fg": "white",
    "button_bg": "#333333",
    "button_fg": "white",
    "entry_bg": "#222222",
    "entry_fg": "white",
    "text_bg": "black",
    "text_fg": "white",
    "selectcolor": "gray"
}

# Flag to track current theme; True means dark theme active
is_dark_theme = True

# Clipboard clear delay in milliseconds (10 seconds)
CLIPBOARD_CLEAR_DELAY_MS = 10000

def apply_theme_to_widget(widget, theme):
    """
    Apply the theme colors to a single widget based on its class.
    """
    cls = widget.winfo_class()
    if cls in ('Toplevel', 'Tk'):
        widget.configure(bg=theme["bg"])

    elif cls == 'Button':
        widget.configure(bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["button_bg"], activeforeground=theme["button_fg"], relief=tk.RAISED)
    
    elif cls == 'Label':
        widget.configure(bg=theme["bg"], fg=theme["fg"])

    elif cls == 'Entry':
        widget.configure(bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["fg"])

    elif cls == 'Text':
        widget.configure(bg=theme["text_bg"], fg=theme["text_fg"], insertbackground=theme["fg"])

    elif cls == 'Checkbutton':
        widget.configure(bg=theme["bg"], fg=theme["fg"], selectcolor=theme["selectcolor"])

    else:
        # For any other widget classes, try to apply bg and fg, ignore errors
        try:
            widget.configure(bg=theme["bg"], fg=theme["fg"])
        except:
            pass

def apply_theme(root_widget, theme):
    """
    Recursively apply the given theme to the root widget and all its children.
    """
    apply_theme_to_widget(root_widget, theme)
    for widget in root_widget.winfo_children():
        apply_theme(widget, theme)

    update_theme_button_text()

def update_theme_button_text():
    """
    Update the theme toggle button text depending on current theme.
    """
    theme_button.config(text="Light Theme" if is_dark_theme else "Dark Theme")

def cancel_clipboard_clear():
    """
    Cancel any scheduled clipboard clearing task if it exists.
    """
    global clipboard_clear_job
    if clipboard_clear_job is not None:
        root.after_cancel(clipboard_clear_job)
        clipboard_clear_job = None  

clipboard_clear_job = None  # Stores after() job ID for clearing clipboard

def clear_clipboard_after_delay(delay_ms=10000):
    """
    Schedule clearing clipboard after specified delay in milliseconds.
    """
    global clipboard_clear_job
    if clipboard_clear_job is not None:
        root.after_cancel(clipboard_clear_job)
    clipboard_clear_job = root.after(delay_ms, root.clipboard_clear)

def toggle_theme():
    """
    Switch between light and dark theme and apply it.
    """
    global is_dark_theme
    is_dark_theme = not is_dark_theme
    theme = dark_theme if is_dark_theme else light_theme
    apply_theme(root, theme)
    theme_button.config(text="Light Theme" if is_dark_theme else "Dark Theme")

def pass_gen_menu():
    """
    Open a popup window to generate a random password of given length.
    Allows saving the password to a plain text file.
    """
    def generate_password():
        try:
            length = int(pass_length_entry.get())
            if length <= 0 or length > 128:  # Limit length for safety
                raise ValueError

            characters = string.ascii_letters + string.digits + string.punctuation
            # Securely generate password using secrets.choice
            password = ''.join(secrets.choice(characters) for _ in range(length))

            result_label.config(text=f"Generated Password:\n{password}")

            # Save password if checkbox is checked
            if chkValue.get():
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                try:
                    with open(FILENAME, "a") as f:
                        f.write(f"[{timestamp}] Length: {length} | {password}\n")

                    encryptFile(FILENAME)
                except Exception as e:
                    print(f"[Save Password Error]: {str(e)}")
            pass_gen_popup.generated_password = password
            copy_button.config(state=tk.NORMAL)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid positive number.")

    def copy_to_clipboard():
        """
        Copy the generated password to system clipboard.
        """
        root.clipboard_clear()
        root.clipboard_append(pass_gen_popup.generated_password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
        clear_clipboard_after_delay()

    # Create password generation popup window
    pass_gen_popup = tk.Toplevel(root)
    pass_gen_popup.title("--- Generate Password ---")
    pass_gen_popup.geometry('400x400')

    label1 = tk.Label(pass_gen_popup, text="Enter Password Length :", font=("Arial", 12))
    label1.pack(pady=5)

    pass_length_entry = tk.Entry(pass_gen_popup, justify='center')
    pass_length_entry.pack(pady=5)

    chkValue = tk.BooleanVar()
    chkValue.set(False)

    save_pass = tk.Checkbutton(pass_gen_popup, text="Save Password", variable=chkValue)
    save_pass.pack(pady=5)

    result_label = tk.Label(pass_gen_popup, text="", wraplength=250, bg='black', fg='lime', font=("Courier", 10))
    result_label.pack(pady=10)

    generate_button = tk.Button(pass_gen_popup, text="Generate", command=generate_password, font=("Arial", 12), width=20, height=2)
    generate_button.pack(pady=5)

    copy_button = tk.Button(pass_gen_popup, text="Copy to Clipboard", command=copy_to_clipboard, font=("Arial", 12), width=20, height=2, state=tk.DISABLED)
    copy_button.pack(pady=5)

    done_button = tk.Button(pass_gen_popup, text="Done", command=pass_gen_popup.destroy, font=("Arial", 12), width=20, height=2)
    done_button.pack(pady=5)

#   label2 = tk.Label(pass_gen_popup, text="Note: The Passwords are saved in a plain text file !!", font=("Arial", 12))
#    label2.pack(pady=5)

    update_theme_button_text()
    apply_theme(pass_gen_popup, dark_theme if is_dark_theme else light_theme)

def passwd_strength_checker_menu():
    """
    Popup window to check the strength of a user-entered password.
    """
    def check_pass():
        user_password = user_input.get().strip()

        if len(user_password) < 8:
            messagebox.showwarning("Warning", "Password contains less than 8 character are weak")
            return

        # Check for presence of lower, upper, digit, and special chars
        has_lower = any(char in string.ascii_lowercase for char in user_password)
        has_upper = any(char in string.ascii_uppercase for char in user_password)
        has_digit = any(char in string.digits for char in user_password)
        has_special = any(char in string.punctuation for char in user_password)

        # Determine strength based on criteria
        if all([has_lower, has_upper, has_digit, has_special]) and len(user_password) >= 12:
            result_label.config(text="Password Strength:\n💪 Strong", fg='lime')
        elif has_lower and has_upper and has_digit:
            result_label.config(text="Password Strength:\n🟡 Normal", fg='yellow')
        else:
            result_label.config(text="Password Strength:\n🔴 Weak", fg='red')

    def toggle_visibility():
        """
        Toggle password entry visibility (show/hide password).
        """
        user_input.config(show='' if show_pass.get() else '*')

    # Create password strength checker popup window
    pass_check_popup = tk.Toplevel(root)
    pass_check_popup.title("--- Password Strength Checker ---")
    pass_check_popup.geometry('400x400')

    label1 = tk.Label(pass_check_popup, text="Enter your password here :", font=("Arial", 12))
    label1.pack(pady=5)

    user_input = tk.Entry(pass_check_popup, justify='center', show='*')
    user_input.pack(pady=5)

    show_pass = tk.BooleanVar()
    toggle_btn = tk.Checkbutton(pass_check_popup, text="Show Password", variable=show_pass, command=toggle_visibility)
    toggle_btn.pack(pady=5)

    result_label = tk.Label(pass_check_popup, text="", font=("Arial", 12))
    result_label.pack(pady=5)

    check_button = tk.Button(pass_check_popup, text="Check Password", command=check_pass, font=("Arial", 12), width=20, height=2)
    check_button.pack(pady=5)

    done_button = tk.Button(pass_check_popup, text="Done", command=pass_check_popup.destroy, font=("Arial", 12),width=20, height=2)
    done_button.pack(pady=5)

    apply_theme(pass_check_popup, dark_theme if is_dark_theme else light_theme)

def hash_gen_menu():
    """
    Popup window to generate SHA-256 hash from user-entered password.
    """
    def hash_password():
        password = user_input.get()
        password_bytes = password.encode('utf-8')
        hash_object = hashlib.sha256(password_bytes)
        hashed_pass = hash_object.hexdigest()
        result_label.config(text=hashed_pass)
        copy_button.config(state=tk.NORMAL)

    def copy_to_clipboard():
        """
        Copy the generated hash to the system clipboard.
        """
        root.clipboard_clear()
        root.clipboard_append(result_label.cget("text"))
        messagebox.showinfo("Copied", "Hash copied to clipboard !!")
        clear_clipboard_after_delay()

    def toggle_visibility():
        """
        Toggle password entry visibility (show/hide password).
        """
        user_input.config(show='' if show_pass.get() else '*')

    # Create hash generator popup window
    hash_gen_popup = tk.Toplevel(root)
    hash_gen_popup.title("--- Hash Generator ---")
    hash_gen_popup.geometry('400x400')

    label1 = tk.Label(hash_gen_popup, text="Enter your password here to generate hash: ")
    label1.pack(pady=5)

    user_input = tk.Entry(hash_gen_popup, justify='center', show='*')
    user_input.pack(pady=5)

    show_pass = tk.BooleanVar()
    toggle_btn = tk.Checkbutton(hash_gen_popup, text="Show Password", variable=show_pass, command=toggle_visibility)
    toggle_btn.pack(pady=5)

    result_label = tk.Label(hash_gen_popup, text="", bg='black', fg='lime', font=("Courier", 10))
    result_label.pack(pady=10)

    gen_hash = tk.Button(hash_gen_popup, text="Generate Hash", command=hash_password, font=("Arial", 12), width=20, height=2)
    gen_hash.pack(pady=5)

    copy_button = tk.Button(hash_gen_popup, text="Copy To Clipboard", command=copy_to_clipboard, font=("Arial", 12), width=20, height=2, state=tk.DISABLED)
    copy_button.pack(pady=5)

    done_button = tk.Button(hash_gen_popup, text="Done", command=hash_gen_popup.destroy, font=("Arial", 12), width=20, height=2)
    done_button.pack(pady=5)

    apply_theme(hash_gen_popup, dark_theme if is_dark_theme else light_theme)

def saved_passwds_menu():
    """
    Popup window to display saved passwords from file in a read-only text area.
    """
    try:
        decryptFile(FILENAME)
        with open(FILENAME, "r") as f:
            saved_passwords = f.read()
    except FileNotFoundError:
        messagebox.showwarning("Warning", "No Saved Passwords Found.")
        return

    saved_passwds_popup = tk.Toplevel(root)
    saved_passwds_popup.title("--- Saved Passwords ---")
    saved_passwds_popup.geometry('600x600')

    text_area = tk.Text(saved_passwds_popup, wrap="word", bg="black", fg="white", font=("Courier", 12))
    text_area.pack(expand=True, fill="both", padx=10, pady=10)

    text_area.insert("1.0", saved_passwords)
    text_area.config(state="disabled")  # Make text read-only
    
    done_button = tk.Button(saved_passwds_popup, text="Done", command=saved_passwds_popup.destroy, font=("Arial", 12), width=20, height=2)
    done_button.pack(pady=5)

    apply_theme(saved_passwds_popup, dark_theme if is_dark_theme else light_theme)

# Main root window setup
root = tk.Tk()
root.title("--- Ultimate Password Manager ---")
root.geometry('640x480')
root.resizable(True, True)

heading1 = tk.Label(root, text="Welcome To Ultimate Password Manager", font=("Arial", 15))
heading1.pack(pady=20)

# Buttons for main features
gen_passwd = tk.Button(root, text="Generate Password", command=pass_gen_menu, font=("Arial", 12), width=20, height=2)
gen_passwd.pack(pady=5)

pass_strength_check = tk.Button(root, text="Password Strength Checker", command=passwd_strength_checker_menu, font=("Arial", 12), width=20, height=2)
pass_strength_check.pack(pady=5)

hash_gen = tk.Button(root, text="Generate Hash", command=hash_gen_menu, font=("Arial", 12), width=20, height=2)
hash_gen.pack(pady=5)

saved_passwds = tk.Button(root, text="Saved Passwords", command=saved_passwds_menu, font=("Arial", 12), width=20, height=2)
saved_passwds.pack(pady=5)

theme_button = tk.Button(root, text="Toggle Theme", command=toggle_theme, font=("Arial", 12), width=20, height=2)
theme_button.pack(pady=5)

exit_button = tk.Button(root, text="Exit", command=root.quit, font=("Arial", 12), width=20, height=2)
exit_button.pack(pady=5)

# Apply initial theme based on is_dark_theme flag
apply_theme(root, dark_theme if is_dark_theme else light_theme)

# When window is closed, cancel any pending clipboard clears and destroy window
root.protocol("WM_DELETE_WINDOW", root.quit)

root.mainloop()
