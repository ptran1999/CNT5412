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


class Client():
    def __init__(self, top):

        KEY_SIZE = 8

        # Connecting animation, set up socket
        self.done = False
        self.client_socket = socket.socket(AF_INET, SOCK_STREAM)

        self.HOST = '127.0.0.1'

        # self.HOST = 'ec2-54-173-78-53.compute-1.amazonaws.com'
        self.PORT = 9995
        # self.PORT = int(input("\nPort: "))
        self.BUFF = 1024
        self.ADDR = (self.HOST, self.PORT)

        self.client_socket.connect(self.ADDR)

        thread_load = Thread(target=self.animate)
        thread_load.start()

        sleep(4)
        self.done = True

        # generate private & public key
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        public = key.publickey().exportKey()
        private = key.exportKey()


        # hashing the public key
        hash_object = hashlib.sha1(public)
        hex_digest = hash_object.hexdigest()

        # send public key to server
        self.client_socket.send(public)

        # receive server answer
        # send hex_digest for server confirmation
        confirm = self.client_socket.recv(1024).decode('utf8')
        if confirm == "YES":
            print("\nconfirmed\n")
            self.client_socket.send(bytes(hex_digest, 'utf8'))

        # Receive server public key:
        getpbk = self.client_socket.recv(1024).decode('utf8')
        print("\nServer public key=\n" + getpbk)

        # Store server public key
        server_pk = RSA.importKey(getpbk)

        # Generate session key and send to server
        if getpbk != "":
            print("\n Making session key.\n")
            # self.key_56 = os.urandom(KEY_SIZE)
            self.key_56 = input("\nPassword: ").encode('utf8')
            # self.key_56 = "abcdefgh".encode('utf8')
            print("\nLength of IV = " + str(len(self.key_56)))
            print("\nSession key = " + str(self.key_56))

            # encrypt session key with server public key
            cipher_rsa = PKCS1_OAEP.new(server_pk)
            enc_sess_key = cipher_rsa.encrypt(self.key_56)
            print("\nEncrypted once session key = " + str(enc_sess_key))

            self.client_socket.send(enc_sess_key)
            print("\nHandshake complete.\n")

            # sending name to server
            self.alias = input("\nYour Name: ")
            self.client_socket.send(bytes(self.alias, 'utf8'))

        # Start GUI
        self.top = top

        self.messages_frame = Frame(self.top)
        myFont = font.Font(family='Helvetica', size=int(x / 70))

        self.my_msg = StringVar()
        self.my_msg.set("Enter message...")

        scrollbar1 = Scrollbar(self.messages_frame)  # To navigate through past messages.

        # Following will contain the messages.
        self.msg_list = Listbox(self.messages_frame, yscrollcommand=scrollbar1.set, height=20, width=75)
        self.msg_list.config(font=myFont, bg='#36393f', fg='#c8c9cb')
        scrollbar1.pack(side=RIGHT, fill=Y)
        self.msg_list.pack(side=TOP, fill=BOTH, expand=1)
        self.messages_frame.pack(side=RIGHT, fill=BOTH, expand=1)

        Thread(target=self.receive).start()

        # User input field and entry button
        entry_field = Entry(self.messages_frame, textvariable=self.my_msg, font=myFont, insertbackground='#c8c9cb',
                            bg='#484c52', fg='#c8c9cb')
        entry_field.bind("<FocusIn>", lambda args: entry_field.delete('0', 'end'))
        if self.my_msg.get() != "Enter message...":
            str_msg = self.my_msg.get()
        else:
            str_msg = ""

        # Enter button for sending
        entry_field.bind("<Return>",
                         lambda send: (self.send(), sleep(.1), entry_field.delete('0', 'end')))
        entry_field.pack(side=LEFT, fill=BOTH, expand=1)

        # Send button
        send_button = Button(self.messages_frame, font=myFont, text="Send",
                             command=lambda: self.send(str_msg, self.key_56),
                             bg='#484c52', fg='#c8c9cb')
        send_button.pack(ipadx=5, ipady=5, side=RIGHT, fill=BOTH)

    def send(self):
        check_msg = self.my_msg.get()
        if check_msg == "QUIT":
            os._exit(0)
        if check_msg != "Enter message...":
            msg = check_msg
            msg = self.alias + ": " + msg
            print(msg)
            print(check_msg)
        sleep(.5)

        cipher = DES.new(self.key_56, DES.MODE_CBC, self.key_56)
        ciphertext = cipher.encrypt((self.padding(check_msg)).encode('utf8'))
        # ciphertext = cipher.encrypt(self.padding(msg))
        print("Encrypted message to server: " + str(ciphertext))
        self.client_socket.send(ciphertext)

    def receive(self):
        while True:
            try:
                msg = self.client_socket.recv(self.BUFF)
                print("Encrypted message from server: " + str(msg))
                d_Msg = self.decrypt(msg, self.key_56)
                print("Plaintext message from server: " + str(d_Msg))
                Pr_Msg = d_Msg[4:-2]
                self.msg_list.insert(END, Pr_Msg)
            except OSError:  # Possibly client has left the chat.
                break

    def animate(self):
        for c in itertools.cycle(['....', '.......', '..........', '............']):
            if self.done:
                break
            sys.stdout.write('\rCONFIRMING CONNECTION TO SERVER ' + c)
            sys.stdout.flush()
            sleep(0.1)

    def padding(self, s):
        return s + ((8 - len(s) % 8) * '`')

    def remove_padding(self, s):
        return s.replace('`', '')

    def decrypt(self, msg, key):
        des_cipher = DES.new(key, DES.MODE_CBC, key)
        plaintext = self.remove_padding((des_cipher.decrypt(msg)).decode('utf8'))
        return plaintext

if __name__ == "__main__":
    root = Tk()
    root.title("CNT5412")
    x = int(root.winfo_screenwidth() / 1.5)
    y = int(root.winfo_screenwidth() / 2.67)
    root.geometry(str(x) + 'x' + str(y))
    Client(root)
    root.mainloop()
