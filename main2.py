import base64
from tkinter import *
from tkinter import PhotoImage
from tkinter import messagebox

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


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = entry_title.get()
    message = entry_secret.get("1.0", END)
    master_secret = entry_key.get()


    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please Enter All İnfo.")
    else:
        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            entry_title.delete(0, END)
            entry_secret.delete("1.0", END)
            entry_key.delete(0, END)

def decrypt():
    message_encrypted = entry_secret.get("1.0", END)
    master_secret = entry_key.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please Enter All İnfo.")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            entry_secret.delete("1.0", END)
            entry_secret.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please Enter Encrypted Text!")


SE_button = Button(text="Save & Encrypt", command=save_and_encrypt)
SE_button.pack()

dec_button = Button(text="Decrypt", command=decrypt)
dec_button.pack()

window.mainloop()