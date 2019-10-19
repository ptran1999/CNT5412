from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from time import sleep

#ADDRESS = {client_socket: (IP, PORT)}
#ONLINE_USERS = {client socket: client_name}
ADDRESS = {}
ONLINE_USERS = {}


HOST = ''
PORT = 9999
BUFF = 1024
ADDR = (HOST, PORT)

# Create server, bind with ADDR
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

#Accept client and take in username
def accept_connections():
    while 1:
        client_socket, client_address = SERVER.accept()
        print("{}:{} connected.". format(client_address[0], client_address[1]))
        ADDRESS[client_socket] = client_address
        username = client_socket.recv(BUFF).decode("utf8")
        ONLINE_USERS[client_socket] = username
        Thread(target=handle_client, args=(client_socket,)).start()

def handle_client(client):
    name = ONLINE_USERS[client]
    welcome = "Welcome,{}! Type QUIT to exit.".format(name)
    msg = "{} connected.".format(name)

    client.send(bytes(welcome,'utf8'))
    sleep(.5)
    broadcast(msg)

    while 1:
        msg = client.recv(BUFF).decode('utf8')
        if msg != "QUIT":
            broadcast(msg, name + ": ")
        else:
            close_connection(client)
            break

#Broadcast msg to chat room
#Prefix is (name + ": ")
def broadcast(msg, prefix=""):
    sent_message = "{}{}".format(prefix, msg)
    print(sent_message)
    try:
        for client in ONLINE_USERS:
            client.send(bytes(sent_message, 'utf8'))
    except:
        pass

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
