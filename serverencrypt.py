from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from time import sleep
import os
import hashlib
import Crypto.Cipher.DES as DES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP


BLOCK_SIZE = 16
KEY_SIZE = 8
DES_mode = DES.MODE_CBC


# Generate private & public RSA server keys
random_generator = Random.new().read
RSAkey = RSA.generate(1024, random_generator)
public_key = RSAkey.publickey().exportKey()
private_key = RSAkey.exportKey()
priv_key_obj = RSA.importKey(private_key)

# Generate hash of public RSA server key
# hash_object = hashlib.sha1(public_key)
# hex_digest = hash_object.hexdigest()

# ADDRESS = {client_socket: (IP, PORT)}
# ONLINE_USERS = {client socket: client_name}
ADDRESS = {}
ONLINE_USERS = {}
skey_l = {}

HOST = '127.0.0.1'
PORT = 9999
BUFF = 1024
ADDR = (HOST, PORT)

# Create server, bind with ADDR
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)


# Accept client and take in username
# Exchanges public keys, verifies integrity, allows connection
def accept_connections():
    while 1:
        client_socket, client_address = SERVER.accept()
        print("{}:{} connected.". format(client_address[0], client_address[1]))
        ADDRESS[client_socket] = client_address

        print("Waiting for client's public key & public key hash\n")
        # Obtains client's public key
        getpbk = client_socket.recv(BUFF)
        print(getpbk)
        # stores client's public key
        client_pk = RSA.importKey(getpbk)
        # Hashes key to check integrity of public key and compares it to client hash
        hash_object = hashlib.sha1(getpbk)
        hex_digest = hash_object.hexdigest()

        if getpbk != "":
            print(getpbk)
            client_socket.send(bytes("YES", 'utf8'))
            gethash = client_socket.recv(BUFF).decode('utf8')
            print("\nHash of public key = " + gethash)
            print()

        # Confirms integrity of client public key:
        if hex_digest == gethash:
            client_socket.send(public_key)

            # Receive session key from client and decrypt
            enc_key = client_socket.recv(BUFF)
            print("*************************")
            print("Encrypted sess_key="+str(enc_key))

            if enc_key != "":
                cipher_rsa = PKCS1_OAEP.new(RSAkey)
                dec_key = cipher_rsa.decrypt(enc_key)
                print("Decrypted sess_key="+str(dec_key))
                print("***************************")
                # Takes in client name and starts thread
                username = client_socket.recv(BUFF)
                ONLINE_USERS[client_socket] = username
                skey_l[username] = dec_key
                Thread(target=handle_client, args=(client_socket, dec_key)).start()


        else:
            print("\n[!] Public key hash doesn't match.\n")
            close_connection(client_socket)


def decrypt(msg, key):
    des_cipher = DES.new(key, DES.MODE_CBC, key)
    plaintext = remove_padding(str(des_cipher.decrypt(msg)))
    return plaintext


def padding(s):
    return s + ((8 - len(s) % 8) * '`')


def remove_padding(s):
    return s.replace('`', '')


# decode client messages
def handle_client(client, key):
    name = ONLINE_USERS[client].decode('utf8')

    sleep(.5)

    while 1:
        ciphertext = client.recv(BUFF)

        plaintext = decrypt(ciphertext, key)

        print("Cipher message from client: " + str(ciphertext))
        print("Plain message from client: " + str(plaintext))

        CBCencrypt = DES.new(skey_l[name.encode('utf8')], DES.MODE_CBC, skey_l[name.encode('utf8')])
        e_msg = CBCencrypt.encrypt(padding(plaintext))

        if plaintext != "QUIT":
            print("Encrypted message to client: " + str(e_msg))
            broadcast(e_msg)
        else:
            close_connection(client)
            break


#Broadcast msg to chat room
#Prefix is (name + ":")

def broadcast(msg):
    for client in ONLINE_USERS:
        client.send(msg)



def close_connection(client):
    client.send(bytes("QUIT", 'utf8'))
    print("{}:{} disconnected.".format(ADDRESS[client][0], ADDRESS[client][1]))
    broadcast("{} disconnected.".format(ONLINE_USERS[client]))
    client.close()
    del ADDRESS[client]
    del ONLINE_USERS[client]


if __name__ == "__main__":
    SERVER.listen(10)
    print("Waiting for connection...")
    accept_connections()
    SERVER.close()
