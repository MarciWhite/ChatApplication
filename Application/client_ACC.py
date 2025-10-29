# MADE BY MARCIWHITE
# DISCLAIMER: THIS IS IN NO WAY SECURE, NEVER TRY TO IMPLEMENT YOUR OWN CRYPTO. THIS WAS DONE AS A PERSONAL EXPERIMENT, WHERE SECURITY WAS NOT A PRIORITY.
import datetime

from datetime import time

import pickle
import socket
import errno
import sys
import threading


import RSA
from cryptography.fernet import Fernet
from tkinter import messagebox as mb
import tkinter as tk
from tkinter import ttk
import sv_ttk


HEADER_LENGTH = 10
USERNAME_LENGTH = 10
MAX_MESSAGE_LENGTH = 2048
MESSAGE_LOAD_LIMIT = 100
IP = "localhost"
PORT = 1234

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Refactor needed, make less global variables, remove not used ones
my_username = None
username = None
username_header = None
f = None
connected = False

def find_in_dict(key, value, list):
    return next((i for i in list if i[key] == value), None)

# class representing the GUI
# inherits from threading.Thread so it can have an infinite loop while rendering the GUI
class App(threading.Thread):
    # Instantiating the class, starting loop
    def __init__(self):
        global f
        super().__init__()
        self.start()
        self.key = Fernet.generate_key()
        self.chatrooms = []
        self.invitations = {"sent":[],"received":[]}
        self.username = None
        self.notifications = [] # {content,read,time}
        self.menu = "login"
        f = Fernet(self.key)
        self.update()
    # creating the gui window
    def run(self):
        global f
        self.root = tk.Tk()
        self.root.title("Chat App")
        self.root.protocol('WM_DELETE_WINDOW')
        self.get_username()
        sv_ttk.set_theme("dark")
        self.root.mainloop()
    # Login/Register page
    def get_username(self):
        frame = ttk.Frame(self.root)
        frame.columnconfigure(0,weight=1)
        frame.columnconfigure(1, weight=1)
        #frame.pack(side="top")

        ttk.Label(frame, text="Username: ").grid(column=0,row=0,sticky="w",padx=5,pady=5)
        e = ttk.Entry(frame)
        e.grid(column=1,row=0,sticky="w",padx=5,pady=5)

        ttk.Label(frame, text="Password: ").grid(column=0,row=1,sticky="w",padx=5,pady=5)
        e_pass = ttk.Entry(frame,show="*")
        e_pass.grid(column=1,row=1,sticky="e",padx=5,pady=5)


        ttk.Button(frame, text="Sign In", command=lambda: self.chat_room(e.get(), e_pass.get()), width=10).grid(column=0,row=2,sticky="w",padx=5,pady=5)
        ttk.Button(frame, text="Sign Up", command=lambda: self.chat_room(e.get(), e_pass.get(), False), width=10,).grid(column=1,row=2,sticky="e",padx=5,pady=5)

        self.check_button = ttk.Checkbutton(frame)
        self.check_button.grid(column=1,row=2,sticky="w",padx=5,pady=5)
        #ttk is dumb
        self.check_button.invoke()
        self.check_button.invoke()

        self.check_button.config(command=lambda: self.toggle(self.check_button,0,e_pass))
        self.check_button.bind("<Enter>",lambda a: self.hover_event(self.check_button,"enter"))
        self.check_button.bind("<Leave>", lambda a: self.hover_event(self.check_button, "leave"))
        frame.pack()
    def toggle(self,widget,action,action_widget=None):
        if action == 0:
            if "selected" in widget.state():
                action_widget.config(show="")
            else:
                action_widget.config(show="*")
    def hover_event(self,widget,type, action=0):
        if action == 0:
            if type == "enter":
                widget.config(text="Show password")
            else:
                widget.config(text="")
    def invite_to_chatroom_GUI(self,_id):
        self.clear()
        frame = ttk.Frame(self.root)
        frame.pack()
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        previous = self.menu
        self.menu = "invite_to_chatroom"
        ttk.Label(frame,text="Invite").grid(column=0,row=0,columnspan=2,sticky="n",padx=5,pady=5)
        ttk.Label(frame,text="Name:").grid(column=0,row=1,sticky="ns",padx=5,pady=5)
        e = ttk.Entry(frame)
        e.grid(column=1,row=1,sticky="e",padx=5,pady=5)
        ttk.Button(frame,command=lambda: self.invite(e.get(),_id), width=30,text="Invite").grid(column=0,row=2,columnspan=2,sticky="n",padx=5,pady=5)
        ttk.Button(frame,command=lambda: self.chat_room(self.username,None,connected=True), width=30,text="Back").grid(column=0,row=3,columnspan=2,sticky="n",padx=5,pady=5)
    def invite(self,name,_id): # not implemented yet
        print(f"Invitation sent for {_id} to {name}")
        raw = {"name":name,"chatroom":_id,"sender":self.username}
        client_socket.send(b"5")
        cipher = f.encrypt(pickle.dumps(raw))
        self.send(cipher)
    def create_chatroom_GUI(self):
        self.menu = "create_chatroom"
        self.clear()
        ttk.Label(self.root, text="Name:").pack()
        e = ttk.Entry(self.root)
        e.pack()
        ttk.Button(self.root, command=lambda: self.create_chatroom(e.get()), width=15,text="Create chatroom").pack()
    def create_chatroom(self,name):
        if name:
            raw_dict = {"name":name,"owner":self.username,"users":[self.username]}
            cipher = f.encrypt(pickle.dumps(raw_dict))
            header = f"{len(cipher):<{HEADER_LENGTH}}".encode()
            client_socket.setblocking(True)
            x = b"2"+header+cipher
            client_socket.send(x)
            client_socket.setblocking(False)
        else:
            self.warn("You have to name the chatroom")

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def warn(self, text):
        mb.showwarning("Alert", text)

    def scrollbar_moved(self):
        print("wow")
    def load_messages(self):
        room = find_in_dict("id", self.current_chatroom, self.chatrooms)
        x = {"mode":"message","from":len(room["messages"]),"chatroom":self.current_chatroom,"limit":MESSAGE_LOAD_LIMIT}
        c = f.encrypt(pickle.dumps(x))
        client_socket.send(b"4")
        self.send(c)
    # Gets called from the login/register page
    def chat_room(self, user_name, password, login=True, connected=False):
        if len(user_name) > USERNAME_LENGTH: return
        self.menu = "chat"
        self.clear()
        self.topframe = ttk.Frame(self.root)
        self.topframe.columnconfigure(0,weight=2)
        self.topframe.columnconfigure(1, weight=5)
        self.topframe.pack()


        print(user_name)
        self.chat = tk.Text(self.topframe,
                            width=50,
                            height=10,
                            bg="#17202A",
                            fg="#EAECEE",
                            font="Helvetica 14",
                            padx=5,
                            pady=5)
        self.chat.config(cursor="arrow")
        self.chat.grid(column=1,row=0,sticky="e",padx=5,pady=5)
        scrollbar = ttk.Scrollbar(self.chat,command=self.scrollbar_moved)
        self.chat.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.chat.yview)

        self.chat.config(state=tk.DISABLED)
        self.group_name = tk.Label(self.chat, text=user_name,anchor=tk.CENTER)
        self.group_name.place(relheight=0.1,relwidth=0.95,rely=0)

        self.notif_button = tk.Button(self.chat, text="0",command=lambda:1)
        self.notif_button.place(rely=0, relx=0.9, relheight=0.1, relwidth=0.05)

        self.load_button = tk.Button(self.chat, text="Load more messages",command=self.load_messages)
        self.load_button.place(rely=0, relx=0,relheight=0.1)
        scrollbar.place(relheight=1,
                        relx=0.954)

        self.e = ttk.Entry(self.topframe)

        self.e.grid(column=1,row=1,sticky="ew",padx=5,pady=5)
        self.e.focus()

        self.root.bind('<Return>', func=lambda a: self.send_message(self.e.get()))
        ttk.Button(self.topframe, command=lambda: self.send_message(self.e.get()), width=10,
                  text="Send").grid(column=0,row=1,sticky="swse",padx=5,pady=5)
        ttk.Button(self.topframe, command=lambda: self.open_invites(), width=10,
                  text="Invites").grid(column=0,row=0,sticky="swse",padx=5,pady=5)
        if not connected:
            self.connect(user_name, password, login)
        else:
            self.logged_in(self.chatrooms)
    def update_notifications(self):
        if (a := len([x for x in self.notifications if not x["read"]])) > 99:
            self.notif_button.config(text="99+")
        else:
            self.notif_button.config(text=a)
    def open_invites(self):
        self.clear()
        self.menu = "invites"
        self.frame = ttk.Frame(self.root)
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=2)
        self.frame.pack()


        scrollbar = ttk.Scrollbar(self.root)

        self.inv_list = tk.Listbox(self.frame, yscrollcommand=scrollbar.set)
        all_invite = self.invitations["received"]+self.invitations["sent"]
        print(all_invite)
        for i in all_invite:
            self.inv_list.insert(tk.END, str(i["chatroom_name"]))

        self.inv_list.grid(column=0,row=0,sticky="nw",padx=5,pady=5,rowspan=3)
        self.inv_list.bind('<<ListboxSelect>>',self.change_invite)
        scrollbar.config(command=self.inv_list.yview)
        self.inv_list = (self.inv_list, self.invitations.copy())
        back = ttk.Button(self.frame, width=25, text="Back",
                  command=lambda: self.chat_room(self.username, None, connected=True))
        if len(all_invite):
            if len(self.invitations["received"]):
                b1 = ttk.Button(self.frame, command=lambda: self.invite_on_click(0), width=10,
                          text="Accept")
                b2 = ttk.Button(self.frame, command=lambda: self.invite_on_click(1), width=10,
                          text="Decline")
                l1 = ttk.Label(self.frame, text=f"From: {all_invite[0]['sender']}\nChatroom: {all_invite[0]['chatroom_name']}")
                l1.grid(column=1,row=0,sticky="n",padx=5,pady=5)
                b1.grid(column=1,row=0,sticky="sw",padx=5,pady=2)
                b2.grid(column=1, row=0, sticky="se", padx=5, pady=2)
                back.grid(column=1,row=1,sticky="n",padx=5,pady=2)
                buttons = [b1,b2,back]

            else:
                b2 = ttk.Button(self.frame, command=lambda: self.invite_on_click(2), width=25,
                               text="Cancel")
                l1 = ttk.Label(self.frame, text=f"To: {all_invite[0]['name']}\nChatroom: {all_invite[0]['chatroom_name']}")
                l1.grid(column=1,row=0,sticky="n",padx=5,pady=5)
                buttons = [b2,back]
                b2.grid(column=1, row=0, sticky="s", padx=5, pady=2)
                back.grid(column=1, row=1, sticky="n", padx=5, pady=2)
            self.selected_invite = {"index": 0, "mode": "received" if len(self.invitations["received"]) else "sent","buttons":buttons,"label":l1}
        else:
            ttk.Label(self.frame, text="No invites yet (no bitches?)").grid(column=1,row=0,sticky="n",padx=5,pady=5)
            back.grid(column=1, row=0, sticky="s", padx=5, pady=2)

    def invite_on_click(self,mode):
        #TODO send clients packet telling them to remove redundant information done, bugfix cancel not working - fixed
        actions = ["accept","delete","cancel"] # + cancel = delete
        index = self.selected_invite["index"]
        all_invite = self.invitations["received"] + self.invitations["sent"]
        raw_dict = {"action":actions[mode],"type":"invite","item":{"chatroom":all_invite[index]["chatroom"],"sender":all_invite[index]["sender"],"name":self.username,"chatroom_name":all_invite[index]["chatroom_name"]}}
        if mode == 0:
            p = pickle.dumps(raw_dict)
            cipher = f.encrypt(p)
            client_socket.send(b"6")
            self.send(cipher)
            self.invitations["received"].remove(all_invite[index])
        elif mode == 1:
            p = pickle.dumps(raw_dict)
            cipher = f.encrypt(p)
            client_socket.send(b"6")
            self.send(cipher)
            self.invitations["received"].remove(all_invite[index])
        elif mode == 2:
            raw_dict = {"action": actions[mode], "type": "invite",
                        "item": {"chatroom": all_invite[index]["chatroom"], "sender": self.username,"name": all_invite[index]["name"],"chatroom_name":all_invite[index]["chatroom_name"]}}
            p = pickle.dumps(raw_dict)
            cipher = f.encrypt(p)
            client_socket.send(b"6")
            self.send(cipher)
            self.invitations["sent"].remove(all_invite[index])
            print("cancel")
        self.open_invites()
    def change_invite(self,event):
        cs = self.inv_list[0].curselection()
        all_invite = self.invitations["received"] + self.invitations["sent"]

        if len(cs) == 0: return
        index = cs[0]
        mode = "received" if index<len(self.invitations["received"]) else "sent"
        for i in self.selected_invite["buttons"]:
            i.destroy()
        self.selected_invite["label"].destroy()
        back = ttk.Button(self.frame, width=25, text="Back",
                          command=lambda: self.chat_room(self.username, None, connected=True))

        if mode == "received":
            b1 = ttk.Button(self.frame,text="Accept",width=10,command=lambda: self.invite_on_click(0))
            b2 = ttk.Button(self.frame,text="Decline",width=10,command=lambda: self.invite_on_click(1))
            l = ttk.Label(self.frame,
                         text=f"From: {all_invite[index]['sender']}\nChatroom: {all_invite[index]['chatroom_name']}")
            self.selected_invite["buttons"] = [b1, b2,back]
            l.grid(column=1, row=0, sticky="n", padx=5, pady=5)
            b1.grid(column=1, row=0, sticky="sw", padx=5, pady=2)
            b2.grid(column=1, row=0, sticky="se", padx=5, pady=2)
            back.grid(column=1, row=1, sticky="n", padx=5, pady=2)
        else:
            l = ttk.Label(self.frame,
                         text=f"To: {all_invite[index]['name']}\nChatroom: {all_invite[index]['chatroom_name']}")
            b2 = ttk.Button(self.frame, command=lambda: self.invite_on_click(2), width=25,
                            text="Cancel")
            l.grid(column=1, row=0, sticky="n", padx=5, pady=5)
            b2.grid(column=1, row=0, sticky="s", padx=5, pady=2)
            back.grid(column=1, row=1, sticky="n", padx=5, pady=2)
            self.selected_invite["buttons"] = [b2, back]
        self.selected_invite["label"] = l
        self.selected_invite.update({"index":index,"mode":mode})


    def change_channel(self, event):
        cs = self.list[0].curselection()
        if len(cs) == 0: return
        index = cs[0]
        room = self.list[1][index]
        self.current_chatroom = room["id"]
        self.display_clear()
        self.display("")
        self.display(f"Successfully connected to {IP} as \"{self.username}\"")
        self.group_name.config(text=room["name"])
        for i in room["messages"]:
            self.display(f"{i['sender']} > {i['content']}")

    def logged_in(self, data):
        if isinstance(data,dict):
            self.chatrooms = data["chatrooms"]
            self.invitations["received"] = data["invitations"]["received"]
            self.invitations["sent"] = data["invitations"]["sent"]

        self.current_chatroom = self.chatrooms[0]["id"]
        self.group_name.config(text=self.chatrooms[0]["name"])
        room = find_in_dict("id", self.current_chatroom, self.chatrooms)
        self.display("")
        self.display(f"Successfully connected to {IP} as \"{self.username}\"")
        for i in room["messages"]:
            self.display(f"{i['sender']} > {i['content']}")
        self.scrollbar = tk.Scrollbar(self.root)

        self.list = tk.Listbox(self.topframe, yscrollcommand=self.scrollbar.set)
        print(self.chatrooms)
        for i in self.chatrooms:
            if i:
                self.list.insert(tk.END, i["name"])

        self.list.grid(column=0,row=0,rowspan=1,sticky="n",padx=5,pady=5)
        self.list.bind('<<ListboxSelect>>', self.change_channel)
        self.list.bind('<Double-Button-1>', self.open_channel)
        self.scrollbar.config(command=self.list.yview)
        self.list = (self.list, self.chatrooms[:])

    def open_channel(self,event):
        cs = self.list[0].curselection()
        if not cs: return
        self.clear()
        self.frame = ttk.Frame(self.root)
        self.frame.columnconfigure(0, weight=2)
        self.frame.columnconfigure(1, weight=1)
        self.frame.pack()

        self.menu = "open_channel"
        index = cs[0]
        room = self.list[1][index]
        ttk.Label(self.frame, text=room["name"]).grid(column=0,row=0,sticky="n",padx=5,pady=5,columnspan=2)

        ttk.Button(self.frame, width=10, text="Invite",
                  command=lambda: self.invite_to_chatroom_GUI(room["id"])).grid(column=0,row=1,sticky="n",padx=5,pady=5)

        ttk.Button(self.frame, width=10, text="Members",
                  command=lambda: self.open_members(room["id"])).grid(column=1,row=1,sticky="n",padx=5,pady=5)

        ttk.Button(self.frame, width=10, text="Back",
                  command=lambda: self.chat_room(self.username, None, connected=True)).grid(column=0,columnspan=2,row=2,sticky="ew",padx=5,pady=5)
    def open_members(self,id):
        self.clear()
        self.menu = "members"
        self.frame = ttk.Frame(self.root)
        self.frame.columnconfigure(0, weight=2)
        self.frame.columnconfigure(1, weight=1)
        self.frame.columnconfigure(2, weight=1)
        self.frame.pack()

        scrollbar = ttk.Scrollbar(self.frame)
        self.member_list = tk.Listbox(self.frame, yscrollcommand=scrollbar.set)

        room = find_in_dict("id",id,self.chatrooms)
        users = room["users"]
        for i in users:
            self.member_list.insert(tk.END, str(i))

        self.member_list.grid(column=0,row=0,rowspan=4,sticky="n",padx=5,pady=5)
        self.member_list.bind('<<ListboxSelect>>', self.change_member)
        scrollbar.config(command=self.member_list.yview)
        self.member_list = (self.member_list, users.copy())
        b1 = ttk.Button(self.frame, command=lambda: 0, width=10,
                               text="Promote")
        b2 = ttk.Button(self.frame, command=lambda: 0, width=10,
                               text="Kick")
        l1 = ttk.Label(self.frame,
                              text=f"{users[0]}",font=("Arial",20))
        l1.grid(column=1,row=0,columnspan=2,sticky="n",padx=5,pady=5)
        buttons = [b1, b2]
        self.selected_member = {"index": 0,"buttons": buttons, "label": l1}

        b1.grid(column=1,row=1,sticky="n",padx=5,pady=5)
        b2.grid(column=2,row=1,sticky="n",padx=5,pady=5)
        ttk.Button(self.frame, width=10, text="Back",
                  command=lambda: self.chat_room(self.username, None, connected=True)).grid(column=1,columnspan=2,row=2,sticky="nenw",padx=5,pady=0)
    def change_member(self,event):
        cs = self.member_list[0].curselection()
        # Todo fix updating the label, update buttons, back button, create chatroom continue button
        #   ask server for the name of the chatroom to display it on invites, if the invite was sent dont name it after the sender on the gui
        users = self.member_list[1]
        if len(cs) == 0: return
        index = cs[0]
        self.selected_member["label"].configure(text=users[index])
        self.selected_member.update({"index": index})
    def send(self,msg):
        header = f"{len(msg):<{HEADER_LENGTH}}".encode()
        client_socket.send(header+msg)
    def connect(self, user_name, password, login=True):
        global username_header, my_username, f, connected, client_socket
        client_socket.connect((IP, PORT))
        # Send a byte representing the type of the action
        if login:
            client_socket.send(b"1")
        else:
            client_socket.send(b"0")
        print(self.key)

        length = int(client_socket.recv(HEADER_LENGTH).strip())
        rsa_key = tuple(int(x) for x in client_socket.recv(length).decode().split(";"))
        c = RSA.encode(self.key, rsa_key).encode()
        print(user_name)
        c_name = f.encrypt(user_name.encode())
        c_pass = f.encrypt(password.encode())
        self.send(c)
        self.send(c_name)
        self.send(c_pass)
        print(rsa_key)
        client_socket.setblocking(False)
        connected = True
        self.username = user_name
        my_username = user_name

    def display(self, msg):
        self.chat.config(state=tk.NORMAL)
        self.chat.insert(tk.END, f"{msg}\n")

        self.chat.config(state=tk.DISABLED)
        self.chat.see(tk.END)

    def display_clear(self):
        self.chat.config(state=tk.NORMAL)
        self.chat.delete("1.0", "end")
        self.chat.config(state=tk.DISABLED)
        self.chat.see(tk.END)

    def send_message(self, message):
        if message:
            # message format: {chatroom: id, sender: name ?, content: message}
            self.e.delete(0, tk.END)
            # Display message locally
            self.display(f'{my_username} > {message}')
            # Create msg_dir including name, chatroom id, message
            msg_dir = {"chatroom": self.current_chatroom, "sender": self.username, "content": message}
            cipher = f.encrypt(pickle.dumps(msg_dir))
            client_socket.send(b"3")
            self.send(cipher)

            # Update locally
            for i in self.chatrooms:
                if i["id"] == msg_dir["chatroom"]:
                    i["messages"].append({"sender": msg_dir["sender"], "content": message})
                    break
            else:
                print("Ayo?")
                return

    def update(self):
        global connected, client_socket
        # Initalize fernet key so it works faster when it matters
        a = f.encrypt(b"sadsad")
        while True:
            if not connected: continue
            try:
                try:
                    mode = int(client_socket.recv(1))
                except ValueError as x:
                    continue

                length = int(client_socket.recv(HEADER_LENGTH).decode())
                print(f"Received a header: {length}")
                r = client_socket.recv(length).decode()
                if not r:
                    print("Disconnected from server!")
                    self.warn("Lost connection to the server please try again!")
                    self.clear()
                    client_socket.close()
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.get_username()
                    connected = False
                    continue
                # Message received
                if mode == 1:
                    msg_dir = pickle.loads(f.decrypt(r.encode()))
                    message = msg_dir["content"]
                    print("Message received!")
                    for i in self.chatrooms:
                        if i["id"] == msg_dir["chatroom"]:
                            i["messages"].append({"sender": msg_dir["sender"], "content": message})
                            room_name = i["name"]
                            break
                    else:
                        continue
                    if msg_dir["chatroom"] == self.current_chatroom and self.menu == "chat":
                        print("Displaying message!")
                        self.display(f"{msg_dir['sender']} > {message}")

                    self.notifications.append({"content":f"{msg_dir['sender']} sent a message to {room_name}","read":False,"time":datetime.time()})
                    self.update_notifications()
                # Warning received
                elif mode == 2:
                    text = r
                    text = f.decrypt(text.encode()).decode()
                    self.warn(text)
                # Login/Register response
                elif mode == 3:
                    print("Response received")
                    serialized = f.decrypt(r.encode())
                    data = pickle.loads(serialized)
                    if data["success"]:
                        if len(data["chatrooms"]) > 0:
                            self.logged_in(data)
                        else:
                            self.create_chatroom_GUI()
                        print("Successfully logged in!")
                    else:
                        self.warn(data["response"])
                        self.clear()
                        client_socket.close()
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.get_username()
                        connected = False
                elif mode == 4: # update chatrooms
                    ch_room = pickle.loads(f.decrypt(r.encode()))
                    self.chatrooms.append(ch_room)
                    # should only call if in create_chatroom_GUI
                    if self.menu == "create_chatroom":
                        self.invite_to_chatroom_GUI(ch_room["id"])
                # update invitations
                elif mode == 5: 
                    inv = pickle.loads(f.decrypt(r.encode()))
                    self.invitations[inv[0]].append(inv[1])
                    if self.menu == "invites":
                        self.open_invites()
                # remove/cancel invitation and update local data structure
                elif mode == 6:
                    dict = pickle.loads(f.decrypt(r.encode()))
                    if dict["action"] == "cancel_invite":
                        self.invitations["received"].remove(dict["item"])
                        if self.menu == "invites":
                            self.open_invites()
                        print("Invitation removed")
                    elif dict["action"] == "delete_invite":
                        print(dict["item"])
                        print(self.invitations["sent"])
                        self.invitations["sent"].remove(dict["item"])

                        if self.menu == "invites":
                            self.open_invites()
                        print("Invitation removed")
                # update messages (load more)
                elif mode == 7:
                    dict = pickle.loads(f.decrypt(r.encode()))
                    for i in self.chatrooms:
                        if i["id"] == dict["chatroom"]:
                            i["messages"] = dict["messages"][::-1] + i["messages"]
                            break
                    else:
                        print(f"Couldn't find chatroom {dict['chatroom']}")

                    if self.menu == "chat":
                        if self.current_chatroom == dict["chatroom"]:
                            room = find_in_dict("id", self.current_chatroom, self.chatrooms)
                            self.display_clear()
                            self.display("")
                            self.display(f"Successfully connected to {IP} as \"{self.username}\"")
                            for i in room["messages"]:
                                self.display(f"{i['sender']} > {i['content']}")
            except IOError as e:
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print(e)
                    sys.exit()

app = App()
