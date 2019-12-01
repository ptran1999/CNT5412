import time
import socket
import threading
import hashlib
import itertools
import sys
import os
from threading import Thread
from tkinter import *
from tkinter import Entry, font
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP

KEY_SIZE = 8
BLOCK_SIZE = 8


class Client():
    def animate(self):
        self.done = False
        for c in itertools.cycle(['....','.......','..........','............']):
            if self.done:
                break
            sys.stdout.write('\rCONFIRMING CONNECTION TO SERVER '+c)
            sys.stdout.flush()
            time.sleep(0.1)

    def __init__(self, top):
        #Setting up socket
        self.server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        #host and port input user
        self.host = '127.0.0.1'
        # port = 9984
        self.port = int(input("\nPort: "))

        #binding the address and port
        self.addr = (self.host, self.port)
        self.server.connect(self.addr)
        thread_load = threading.Thread(target=self.animate)
        thread_load.start()
        time.sleep(4)
        self.done = True

        #public key and private key
        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator)
        self.public = self.key.publickey().exportKey()
        self.private = self.key.exportKey()
        self.pub_key_obj = RSA.importKey(self.public)

        #hashing the public key
        self.hash_object = hashlib.sha1(self.public)
        self.hex_digest = self.hash_object.hexdigest()

        # while True:
        self.server.send(self.public)
        confirm = self.server.recv(1024).decode('utf8')
        if confirm == "YES":
            # print("\nconfirmed\n")
            self.server.send(bytes(self.hex_digest, 'utf8'))
        # Receive server public key:
        getpbk = self.server.recv(1024).decode('utf8')
        print("\nServer public key=\n" + getpbk)
        # Store server public key
        self.server_pk = RSA.importKey(getpbk)

        if getpbk != "":
            # Generate session key:
            # Generate 56 bit random key
            key_56 = os.urandom(KEY_SIZE)
            print("\nSession key=" + str(key_56))

           # CONFIDENTIALITY:
            # Encrypt with server public key:
            cipher_rsa = PKCS1_OAEP.new(self.server_pk)
            enc_sess_key = cipher_rsa.encrypt(key_56)
            print("\nEncrypted once session key=" + str(enc_sess_key))

            # INTEGRITY:
            # Hash encryption and send to server:
            # cipher_rsa = PKCS1_OAEP.new(key)
            # enc2_sess_key = cipher_rsa.encrypt(enc_sess_key)
            # print("\nEncrypted twice session key=" + str(enc2_sess_key))
            print("\nHandshake complete.\n")
            self.server.send(enc_sess_key)
            alias = input("\nYour Name: ")
            self.server.send(bytes(alias, 'utf8'))
        #
        # while True:
        #
            # thread_send = threading.Thread(target=self.send, args=("------Sending Message------", alias, key_56))
            print("\nThreading.\n")
            thread_recv = threading.Thread(target=self.recv, args=("------Recieving Message------", key_56))
            # thread_send.start()
            thread_recv.start()

            # thread_send.join()
            thread_recv.join()
            self.top = top

            self.messages_frame = Frame(self.top)
            myFont = font.Font(family='Helvetica', size=int(x / 70))

            receive_thread = Thread(target=self.recv)
            receive_thread.start()

            self.my_msg = StringVar()
            self.my_msg.set("Enter message...")

            scrollbar1 = Scrollbar(self.messages_frame)  # To navigate through past messages.

            # Following will contain the messages.
            self.msg_list = Listbox(self.messages_frame, yscrollcommand=scrollbar1.set, height=20, width=75)
            self.msg_list.config(font=myFont, bg='#36393f', fg='#c8c9cb')
            scrollbar1.pack(side=RIGHT, fill=Y)
            self.msg_list.pack(side=TOP, fill=BOTH, expand=1)
            self.messages_frame.pack(side=RIGHT, fill=BOTH, expand=1)

            # User input field and entry button
            entry_field = Entry(self.messages_frame, textvariable=self.my_msg, font=myFont,
                                insertbackground='#c8c9cb',
                                bg='#484c52', fg='#c8c9cb')
            entry_field.bind("<FocusIn>", lambda args: entry_field.delete('0', 'end'))
            if self.my_msg.get() != "Enter message...":
                str_msg = self.my_msg.get()
            else:
                str_msg = ""
            entry_field.bind("<Return>", lambda send: (self.send("Sending", str_msg, key_56),
                                                       time.sleep(.1), entry_field.delete('0', 'end')))
            entry_field.pack(side=LEFT, fill=BOTH, expand=1)
            # Enter button
            send_button = Button(self.messages_frame, font=myFont, text="Send", command=lambda: self.send(str_msg),
                                 bg='#484c52', fg='#c8c9cb')
            send_button.pack(ipadx=5, ipady=5, side=RIGHT, fill=BOTH)
            time.sleep(0.5)
        time.sleep(60)
        self.server.close()


    def padding(self, s):
        return s + ((8 - len(s) % 8) * '`')


    def remove_padding(self, s):
        return s.replace('`', '')


    # working ???
    def send(self, t, msg, key):
        # mess = input(name + " : ")
        #merging the message and the name
        # data = name+" : "+mess
        cipher = DES.new(key, DES.MODE_CBC, key)
        ciphertext = cipher.encrypt(self.padding(msg))
        # print("\nLength of ciphertext=" +str(len(ciphertext)))
        if cipher != "":
            print("ENCRYPTED MESSAGE TO SERVER-> "+str(ciphertext))
        self.server.send(ciphertext)


    # should display ciphertext received and plaintext
    def recv(self, t,key):
        ciphertext = self.server.recv(1024)
        print("\nENCRYPTED MESSAGE FROM SERVER-> " + str(ciphertext))
        # key = key[:16]
        dec_key = DES.new(key, DES.MODE_CBC, key)
        plaintext = self.remove_padding(str(dec_key.decrypt(ciphertext)))
        print("\n**New Message From Server**  " +
              time.ctime(time.time()) + " : " + str(plaintext) + "\n")

    def delete_screen(self, x):
        x.destroy()


if __name__ == "__main__":
    root = Tk()
    root.title("CNT5412")
    x = int(root.winfo_screenwidth() / 1.5)
    y = int(root.winfo_screenwidth() / 2.67)
    root.geometry(str(x) + 'x' + str(y))
    Client(root)
    root.mainloop()







