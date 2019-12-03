from tkinter import *
from tkinter import Entry, font
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from time import sleep
import hashlib
import itertools
import sys
import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP


""" CONNECT SOCKET """
s = socket()
host = '127.0.0.1'
print("Bob's host : ", host)
port = 8080
BUFF = 1024
s.bind((host, port))
print("Bob is waiting for incoming connections")
print("")
s.listen(1)
Bob, addr = s.accept()
print(addr, " has connected to Bob and is now online ...")
print("")


""" GENERATE KEY """
# generate private & public key
random_generator = Random.new().read
B_private = RSA.generate(1024, random_generator)
B_public = B_private.publickey().exportKey()


# hashing the public key
hash_object = hashlib.sha1(B_public)
hex_digest = hash_object.hexdigest()


""" START KEY EXCHANGE """
print("Waiting for Alice's public key & public key hash\n")
# Obtains Alice's public key
A_pbk_encrypt = Bob.recv(BUFF)
print("Alice's public key:\n", A_pbk_encrypt)
# stores Alice's public key
A_pbk = RSA.importKey(A_pbk_encrypt)
# Hashes key to check integrity of public key and compares it to Alice's hash
hash_object = hashlib.sha1(A_pbk_encrypt)
hex_digest = hash_object.hexdigest()

if A_pbk_encrypt != "":
    Bob.send(bytes("YES", 'utf8'))
    # get Alice hash public key
    gethash = Bob.recv(BUFF).decode('utf8')
    print("\nHash of public key from Alice: " + gethash)
    print()

# Confirms integrity of Alice's public key:
if hex_digest == gethash:
    Bob.send(B_public)

    # Receive session key from client and decrypt
    enc_key = Bob.recv(BUFF)
    print("*************************")
    print("Encrypted secret key:\n" + str(enc_key))

    if enc_key != "":
        cipher_rsa = PKCS1_OAEP.new(B_private)
        dec_key = cipher_rsa.decrypt(enc_key)
        print("Decrypted secret key:\n" + str(dec_key))
        print("***************************")
        print("\nHandshake complete!\n")

else:
    print("\n[!] Public key hash doesn't match.\n")

""" END KEY EXCHANGE """

""" ENCRYPTION & DECRYPTION """


def padding(s):
    return s + ((8 - len(s) % 8) * '`')


def remove_padding(s):
    return s.replace('`', '')


def encrypt(msg, key):
    des_cipher = DES.new(key, DES.MODE_CBC, key)
    ciphertext = des_cipher.encrypt(padding(msg).encode('utf8'))
    return ciphertext


def decrypt(msg, key):
    des_cipher = DES.new(key, DES.MODE_CBC, key)
    plaintext = remove_padding(des_cipher.decrypt(msg).decode('utf8'))
    return plaintext


""" SEND & RECEIVE MESSAGE """

def send():
    msg = my_msg.get()
    if msg != "QUIT":
        # encrypt and send the message
        s_msg = encrypt(msg, dec_key)
        Bob.send(s_msg)

        # Put in the GUI
        Pr_Msg = "Bob encrypted message: " + str(s_msg)
        msg_list.insert(END, Pr_Msg)
    else:
        s_msg = encrypt("Bob has quit!", dec_key)
        Bob.send(s_msg)
        root.destroy()


def recv():
    while 1:
        # receive and decrypt message
        msg = Bob.recv(1024)
        r_msg = decrypt(msg, dec_key)

        # Put in the GUI
        Pr_Msg = "Alice encrypted message:" + str(msg)
        msg_list.insert(END, Pr_Msg)
        Pr_Msg = "Alice: " + str(r_msg)
        msg_list.insert(END, Pr_Msg)


""" GUI """

root = Tk()
root.title("BOB")
x = int(root.winfo_screenwidth() / 1.5)
y = int(root.winfo_screenwidth() / 2.67)
root.geometry(str(x) + 'x' + str(y))
messages_frame = Frame(root)
myFont = font.Font(family='Helvetica', size=int(x / 70))
my_msg = StringVar()
my_msg.set("Enter message...")

scrollbar1 = Scrollbar(messages_frame)  # To navigate through past messages.

# Following will contain the messages.
msg_list = Listbox(messages_frame, yscrollcommand=scrollbar1.set, height=20, width=75)
msg_list.config(font=myFont, bg='#36393f', fg='#c8c9cb')
scrollbar1.pack(side=RIGHT, fill=Y)
msg_list.pack(side=TOP, fill=BOTH, expand=1)
messages_frame.pack(side=RIGHT, fill=BOTH, expand=1)

Thread(target=recv).start()

# User input field and entry button
entry_field = Entry(messages_frame, textvariable=my_msg, font=myFont, insertbackground='#c8c9cb',
                    bg='#484c52', fg='#c8c9cb')
entry_field.bind("<FocusIn>", lambda args: entry_field.delete('0', 'end'))
if my_msg.get() != "Enter message...":
     str_msg = my_msg.get()
else:
     str_msg = ""

# Enter button for sending
entry_field.bind("<Return>",
                         lambda send: (send(), sleep(.1), entry_field.delete('0', 'end')))
entry_field.pack(side=LEFT, fill=BOTH, expand=1)

# Send button
send_button = Button(messages_frame, font=myFont, text="Send", command=lambda: send(), bg='#484c52', fg='#c8c9cb')
send_button.pack(ipadx=5, ipady=5, side=RIGHT, fill=BOTH)


root.mainloop()


