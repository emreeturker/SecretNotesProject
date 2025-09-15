import json
from tkinter import *
from cryptography.fernet import Fernet
from tkinter import PhotoImage
from tkinter import messagebox
import os

window = Tk()
window.title("Secret Notes")
window.minsize(width=400, height=650)
window.config(padx=30, pady=30)

image = PhotoImage(file="ımg.png")
image = image.subsample(5,5)
image_label = Label(image=image)
image_label.pack(pady=(0,25))

label_title = Label(text="Enter Your Title", font=("Arial", 12, "bold"))
label_title.pack()

entry_title = Entry(width=35)
entry_title.pack()

label_secret = Label(text="Enter Your Secret", font=("Arial", 12, "bold"))
label_secret.pack()

entry_secret = Text(width=40, height=15)
entry_secret.pack()

label_key = Label(text="Enter Master Key", font=("Arial", 12, "bold"))
label_key.pack()

entry_key = Entry(width=35)
entry_key.pack()

BASE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE, "diary.key")
DIARY_FILE = os.path.join(BASE, "diary.enc")

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

fernet = Fernet(load_key())

def encrypt_inputs():
    title_plain = entry_title.get().encode("utf-8")
    secret_plain = entry_secret.get("1.0", "end-1c").encode("utf-8")

    title_enc = fernet.encrypt(title_plain).decode("utf-8")
    secret_enc = fernet.encrypt(secret_plain).decode("utf-8")

    entry_title.delete(0, "end")
    entry_title.insert(0, title_enc)

    entry_secret.delete("1.0", "end")
    entry_secret.insert("1.0", secret_enc)

def decrypt_inputs():
    try:
        title_enc = entry_title.get().encode("utf-8")
        secret_enc = entry_secret.get("1.0", "end-1c").encode("utf-8")

        title_plain = fernet.decrypt(title_enc).decode("utf-8")
        secret_plain = fernet.decrypt(secret_enc).decode("utf-8")
    except Exception as e:
        entry_secret.delete("1.0", "end")
        entry_secret.insert("1.0", f"Decryption error: {e}")
        return
    entry_title.delete(0, "end")
    entry_title.insert(0, title_plain)

    entry_secret.delete("1.0", "end")
    entry_secret.insert("1.0", secret_plain)

def save_encrypted_to_file(path=DIARY_FILE):
    data = {"title": entry_title.get(), "secret": entry_secret.get("1.0", "end-1c")}
    blob = json.dumps(data).encode("utf-8")
    token = fernet.encrypt(blob)
    with open(path, "wb") as f:
        f.write(token)

def load_encrypted_from_file(path=DIARY_FILE):
    if not os.path.exists(path):
        return
    with open(path, "rb") as f:
        token = f.read()
    plain = fernet.decrypt(token)
    obj = json.loads(plain.decode("utf-8"))

    entry_title.delete(0, "end")
    entry_title.insert(0, obj.get("title", ""))


SE_button = Button(text="Save & Encrypt", command=save_encrypted_to_file)
SE_button.pack()

dec_button = Button(text="Decrypt", command=decrypt_inputs)
dec_button.pack()

window.mainloop()

