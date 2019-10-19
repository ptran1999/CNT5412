from tkinter import *
from tkinter import Entry, font
from socket import AF_INET,socket, SOCK_STREAM
from threading import Thread
from time import sleep
import os

class Client():
    def __init__(self, top):
        self.client_socket = socket(AF_INET, SOCK_STREAM)

        #self.HOST = '127.0.0.1'

        self.HOST = 'ec2-54-173-78-53.compute-1.amazonaws.com'
        self.PORT = 9999

        self.BUFF = 1024
        self.ADDR = (self.HOST, self.PORT)

        print("trying to connect")
        self.client_socket.connect(self.ADDR)
        print("Connected")

        self.top = top

        self.messages_frame = Frame(self.top)
        myFont = font.Font(family='Helvetica', size=int(x / 70))

        receive_thread = Thread(target=self.receive)
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
        entry_field = Entry(self.messages_frame, textvariable=self.my_msg, font=myFont, insertbackground='#c8c9cb',
                            bg='#484c52', fg='#c8c9cb')
        entry_field.bind("<FocusIn>", lambda args: entry_field.delete('0', 'end'))
        if self.my_msg.get() != "Enter message...":
            str_msg = self.my_msg.get()
        else:
            str_msg = ""
        entry_field.bind("<Return>", lambda send: (self.send(str_msg), sleep(.1), entry_field.delete('0', 'end')))
        entry_field.pack(side=LEFT, fill=BOTH, expand=1)
        # Enter button
        send_button = Button(self.messages_frame, font=myFont, text="Send", command=lambda: self.send(str_msg),
                             bg='#484c52', fg='#c8c9cb')
        send_button.pack(ipadx=5, ipady=5, side=RIGHT, fill=BOTH)

    def send(self, msg, event=None):
        check_msg = self.my_msg.get()
        if check_msg != "Enter message...":
            msg = check_msg
            print(msg)
        sleep(.5)
        self.client_socket.send(bytes(msg, 'utf8'))
        if msg == "QUIT":
            os._exit(0)

    def receive(self):
        while True:
            try:
                msg = self.client_socket.recv(self.BUFF).decode('utf8')
                self.msg_list.insert(END, msg)
            except OSError:  # Possibly client has left the chat.
                break


if __name__ == "__main__":
    root = Tk()
    root.title("CNT5412")
    x = int(root.winfo_screenwidth()/1.5)
    y = int(root.winfo_screenwidth()/2.67)
    root.geometry(str(x) + 'x' + str(y))
    Client(root)
    root.mainloop()