from tkinter import *
from tkinter import Entry, font
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from time import sleep
import socket
import hashlib
import itertools
import sys
import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP

KEY_SIZE = 8

""" CONNECT SOCKET """
Alice = socket.socket()
host = '127.0.0.1'
port = 8080
BUFF = 1024
Alice.connect((host, port))
print("Connected to Bob")

""" GENERATE KEY """
# generate private & public key
random_generator = Random.new().read
A_private = RSA.generate(1024, random_generator)
A_public = A_private.publickey().exportKey()


# hashing the public key
hash_object = hashlib.sha1(A_public)
hex_digest = hash_object.hexdigest()

""" START KEY EXCHANGE """
# send public key to server
Alice.send(A_public)

# receive server answer
# send hex_digest for server confirmation
confirm = Alice.recv(1024).decode('utf8')
if confirm == "YES":
    print("I got Bob's public key")
    Alice.send(bytes(hex_digest, 'utf8'))

# Receive server public key:
getpbk = Alice.recv(1024).decode('utf8')
print("Bob's public key:\n" + getpbk)

# Store server public key
server_pk = RSA.importKey(getpbk)

# Generate session key and send to server
if getpbk != "":
    print("\n***********************")
    key_56 = os.urandom(KEY_SIZE)
    print("Secret key: \n" + str(key_56))

    # encrypt session key with server public key
    cipher_rsa = PKCS1_OAEP.new(server_pk)
    enc_sess_key = cipher_rsa.encrypt(key_56)
    print("Encrypted secret key: \n" + str(enc_sess_key))
    print("************************")
    Alice.send(enc_sess_key)
    print("\nHandshake complete!\n")
""" END KEY CHANGE"""

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


# """ GUI """
#
# root = Tk()
# root.title("ALICE AND BOB")
# x = int(root.winfo_screenwidth() / 1.5)
# y = int(root.winfo_screenwidth() / 2.67)
# root.geometry(str(x) + 'x' + str(y))
#
# messages_frame = Frame(root)
# myFont = font.Font(family='Helvetica', size=int(x / 70))
#
# my_msg = StringVar()
# my_msg.set("Enter message...")
#
# scrollbar1 = Scrollbar(messages_frame)  # To navigate through past messages.
#
# # Following will contain the messages.
# msg_list = Listbox(messages_frame, yscrollcommand=scrollbar1.set, height=20, width=75)
# msg_list.config(font=myFont, bg='#36393f', fg='#c8c9cb')
# scrollbar1.pack(side=RIGHT, fill=Y)
# msg_list.pack(side=TOP, fill=BOTH, expand=1)
# messages_frame.pack(side=RIGHT, fill=BOTH, expand=1)
#
# # User input field and entry button
# entry_field = Entry(messages_frame, textvariable=my_msg, font=myFont, insertbackground='#c8c9cb',
#                     bg='#484c52', fg='#c8c9cb')
# entry_field.bind("<FocusIn>", lambda args: entry_field.delete('0', 'end'))
# if my_msg.get() != "Enter message...":
#     str_msg = my_msg.get()
# else:
#     str_msg = ""
#
# # Enter button for sending
# entry_field.pack(side=LEFT, fill=BOTH, expand=1)
#
# # Send button
# send_button = Button(messages_frame, font=myFont, text="Send",
#                      command=lambda: send(str_msg),
#                      bg='#484c52', fg='#c8c9cb')
# send_button.pack(ipadx=5, ipady=5, side=RIGHT, fill=BOTH)


""" SEND & RECEIVE MESSAGE """


def send(msg):
    s_msg = encrypt(msg, key_56)
    Alice.send(s_msg)
    print("Alice encrypted message: ", s_msg)
    # Pr_Msg = "Alice encrypted message: " + str(s_msg)
    # msg_list.insert(END, Pr_Msg)

def recv():
    msg = Alice.recv(1024)
    r_msg = decrypt(msg, key_56)
    print("Bob encrypted message:", msg)
    print("Bob: ", r_msg)
    # Pr_Msg = "Bob encrypted message:" + str(msg)
    # msg_list.insert(END, Pr_Msg)
    # Pr_Msg = "Bob: " + str(r_msg)
    # msg_list.insert(END, Pr_Msg)

# Start chatting part
while 1:
    recv()
    msg = input(">> ")
    send(msg)
    # root.mainloop()