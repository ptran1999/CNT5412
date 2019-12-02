import time
import socket
import threading
import hashlib
import itertools
import sys
import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP

KEY_SIZE = 8
BLOCK_SIZE = 8

# animating loading
done = False

def animate():
    for c in itertools.cycle(['....', '.......', '..........', '............']):
        if done:
            break
        sys.stdout.write('\rCONFIRMING CONNECTION TO SERVER '+c)
        sys.stdout.flush()
        time.sleep(0.1)


# Setting up socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# host and port input user
host = '127.0.0.1'
port = 9983


# binding the address and port
server.connect((host, port))
# printing "Server Started Message"
thread_load = threading.Thread(target=animate)
thread_load.start()

time.sleep(4)
done = True

# public key and private key
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)
public = key.publickey().exportKey()
private = key.exportKey()

pub_key_obj = RSA.importKey(public)

# hashing the public key
hash_object = hashlib.sha1(public)
hex_digest = hash_object.hexdigest()


def padding(s):
    return s + ((8 - len(s) % 8) * '`')


def remove_padding(s):
    return s.replace('`', '')


# working ???
def send(t, name, key):
    mess = input(name + " : ")
    # merging the message and the name
    data = name+" : "+mess
    cipher = DES.new(key, DES.MODE_CBC, key)
    ciphertext = cipher.encrypt(padding(mess))
    print("Length of cipher text = " + str(len(ciphertext)))
    if cipher != "":
        print("Encrypted message to server: " + str(ciphertext))
    server.send(ciphertext)


# RAW
def recv(t, key):
    newmess = server.recv(1024)
    print("Encrypted message from server: " + str(newmess))
    decoded = newmess.decode('utf8')
    CBCdecrypt = DES.new(key, DES.MODE_CBC, counter=lambda: key)
    dMsg = CBCdecrypt.decrypt(decoded)
    # print("\n**New Message From Server**  " + time.ctime(time.time()) + " : " + dMsg + "\n")


while True:
    server.send(public)
    confirm = server.recv(1024).decode('utf8')
    if confirm == "YES":
        print("\nconfirmed\n")
        server.send(bytes(hex_digest, 'utf8'))
    # Receive server public key:
    getpbk = server.recv(1024).decode('utf8')
    print("\nServer public key=\n" + getpbk)
    # Store server public key
    server_pk = RSA.importKey(getpbk)

    if getpbk != "":
        # Generate session key:
        print("\n Making session key.\n")
        # Generate 56 bit random key
        key_56 = os.urandom(KEY_SIZE)
        print("\nLength of IV = " + str(len(key_56)))
        print("\nSession key = " + str(key_56))
        # Encrypt with client private key
        # cipher_rsa = PKCS1_OAEP.new(key)
        # enc_sess_key = cipher_rsa.encrypt(key_56)

    # CONFIDENTIALITY:
    # Encrypt with server public key:
        cipher_rsa = PKCS1_OAEP.new(server_pk)
        enc_sess_key = cipher_rsa.encrypt(key_56)
        print("\nEncrypted once session key = "+str(enc_sess_key))

    #INTEGRITY:
    #Hash encryption and send to server:
        # cipher_rsa = PKCS1_OAEP.new(key)
        # enc2_sess_key = cipher_rsa.encrypt(enc_sess_key)
        # print("\nEncrypted twice session key=" + str(enc2_sess_key))
        print("\nHandshake complete.\n")
        server.send(enc_sess_key)
        alias = input("\nYour Name: ")
        server.send(bytes(alias, 'utf8'))


    while True:
        thread_send = threading.Thread(target=send, args=("------Sending Message------", alias, key_56))
        thread_recv = threading.Thread(target=recv, args=("------Receiving Message------", key_56))
        thread_send.start()
        thread_recv.start()

        thread_send.join()
        thread_recv.join()
        time.sleep(0.5)
    time.sleep(60)
    server.close()





