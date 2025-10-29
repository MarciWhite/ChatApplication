#MADE BY MARCIWHITE
# DISCLAIMER: THIS IS IN NO WAY SECURE, NEVER TRY TO IMPLEMENT YOUR OWN CRYPTO. THIS WAS DONE AS A PERSONAL EXPERIMENT, WHERE SECURITY WAS NOT A PRIORITY.
import datetime
import socket
import select
import time

import RSA
from cryptography.fernet import Fernet
import pymongo
import pickle

HEADER_LENGTH = 10
MAX_MESSAGE_LENGTH = 2048
TYPE_HEADER = 1
IP = "localhost"
PORT = 1234
debug_logger = True
TYPES = ["register","login","create_chatroom","message","get","invite","edit"]
# Database
client = pymongo.MongoClient(
    "<YOUR MONGO DB CONNECTION STRING HERE>")
db = client.Chat
col = db.Main

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind, so server informs operating system that it's going to use given IP and port
server_socket.bind(('', PORT))

# This makes server listen to new connections
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data
clients = {}
keys = {}
print(f'Listening for connections on {IP}:{PORT}...')

# MODES:
# 1 - Normal message
# 2 - Warn


# Handles message receiving
def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode().strip())
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:
        return False

def get_user_info(client_socket):
    header = client_socket.recv(HEADER_LENGTH) # slow part
    if not len(header):
        return False
    name = client_socket.recv(int(header.decode().strip()))
    header = client_socket.recv(HEADER_LENGTH)
    password = client_socket.recv(int(header.decode().strip()))
    fernet_key = keys[client_socket][1]
    f = Fernet(fernet_key.encode())
    name = f.decrypt(name)
    password = f.decrypt(password)
    return {"name": name.decode(), "password": password.decode()}

def create_chatroom(users, owner, name):
    doc = col.find_one({"type": "chatrooms"})
    user_doc = col.find_one({"type":"info"})
    all_user = user_doc["users"]
    rooms = doc["chatrooms"]
    _id = doc["count"] + 1
    # users array also contains the owner
    for i in users:
        print(users)
        print([x["name"] for x in all_user])
        for j in all_user:
            if i == j["name"]:
                j["chatrooms"].append(_id)
                print("asd")
                break
    else:
        print("?")
    ch_room = {"id": _id, "owner": owner, "users": users, "creation_time": time.time(), "messages": [], "name": name,"invitations":[]}
    rooms.append(ch_room)
    col.update_one({"type":"info"}, {"$set":{"users":all_user}})
    col.update_one({"type": "chatrooms"}, {"$set": {"chatrooms": rooms}, "$inc": {"count": 1}})
    return ch_room
def get_chatroom(_id,msg_limit=100):
    doc = col.find_one({"type": "chatrooms"})
    rooms = doc["chatrooms"]
    for i in rooms:
        if i["id"] == _id:
            if msg_limit != None:
                i["messages"] = i["messages"][::-1][:msg_limit]
            return i
    return None
def get_invites(name,type):
    user_doc = col.find_one({"type": "info"})
    all_user = user_doc["users"]
    if type == "received":
        if res := [x["invitations"] for x in all_user if x["name"]==name]:
            return res[0]
        return []
    elif type == "sent":
        res = []
        rooms = next(iter([x["chatrooms"] for x in all_user if x["name"] == name]),[])
        for i in rooms:
            if r:=get_chatroom(i):
                for j in r["invitations"]:
                    if j["sender"] == name:
                        j.update({"chatroom":r["id"]})
                        res.append(j)
        return res

def invite(chatroom,name,sender):
    doc = col.find_one({"type": "chatrooms"})
    user_doc = col.find_one({"type": "info"})
    all_user = user_doc["users"]
    rooms = doc["chatrooms"]
    chatroom_name = "Not found"
    if [x for x in all_user if x["name"]==name]:
        for i in rooms:
            if i["id"]==chatroom:
                i["invitations"].append({"name":name,"sender":sender})
                chatroom_name = i["name"]
                break
        else:
            print(f"Something went wrong, while trying to invite {name}")
            return False

        for i in all_user:
            if i["name"]==name:
                i["invitations"].append({"chatroom":chatroom,"sender":sender,"time":time.time(),"chatroom_name":chatroom_name})
                break
        else:
            print(f"Something went wrong, while trying to invite {name}")
            return False


    else:
        print(f"Noone was found with the name: {name}")
        return False
    col.update_one({"type": "info"}, {"$set": {"users": all_user}})
    col.update_one({"type": "chatrooms"}, {"$set": {"chatrooms": rooms}})
    return {"chatroom":chatroom,"name":name,"sender":sender,"chatroom_name":chatroom_name}
def delete_invite(chatroom,name,sender,chatroom_name):
    doc = col.find_one({"type": "chatrooms"})
    user_doc = col.find_one({"type": "info"})
    all_user = user_doc["users"]
    rooms = doc["chatrooms"]
    if len([x for x in all_user if x["name"]==name]):
        for i in all_user:
            if i["name"]==name:
                print("ASD1.1")
                print(i)
                for j in i["invitations"]:
                    print(j)
                    if j["chatroom"] == chatroom and j["sender"] == sender:
                        i["invitations"].remove(j)
                        print("ASD1")
                        break
                break
        else:
            print(f"Something went wrong, while trying to delete invite {name}")
            return False

        for i in rooms:
            if i["id"]==chatroom:
                for j in i["invitations"]:
                    if j["name"] == name and j["sender"] == sender:
                        i["invitations"].remove(j)
                        print("ASD2")
                        break
                break
        else:
            print(f"Something went wrong, while trying to delete invite {name}")
            return False
    else:
        print(f"Noone was found with the name: {name}")
        return False
    col.update_one({"type": "info"}, {"$set": {"users": all_user}})
    col.update_one({"type": "chatrooms"}, {"$set": {"chatrooms": rooms}})
    return True
def upload_message(_id,msg,user):
    doc = col.find_one({"type": "chatrooms"})
    rooms = doc["chatrooms"]
    for i in rooms:
        if i["id"] == _id:
            msg_dir = {"sender":user,"content":msg,"time":time.time()}
            i["messages"].append(msg_dir)
    col.update_one({"type": "chatrooms"}, {"$set": {"chatrooms": rooms}})

while True:

    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    # Iterate over notified sockets
    for notified_socket in read_sockets:
        # If notified socket is a server socket - new connection, accept it
        if notified_socket == server_socket:

            # Accept new connection
            # That gives us new socket - client socket, connected to this given client only, it's unique for that client
            # The other returned object is ip/port set
            client_socket, client_address = server_socket.accept()
            # Mode:
            n = int(client_socket.recv(TYPE_HEADER).decode())
            type = TYPES[n]
            if debug_logger:
                print(f"Connection accepted, type: {type}")
            # Key exchange
            print("Generating rsa keys")
            rsa_key = RSA.generate_keys(500)
            print("Done")
            s = ";".join([str(x) for x in rsa_key["public"]])
            client_socket.send(f"{len(s):<{HEADER_LENGTH}}".encode())
            client_socket.send(s.encode())

            length = int(client_socket.recv(HEADER_LENGTH).strip())
            fernet = client_socket.recv(length)
            fernet = RSA.decode([int(x) for x in fernet.decode().split(";")], rsa_key["private"])
            keys[client_socket] = (rsa_key, fernet)
            username = None

            success = False
            reason = "None"
            info = col.find_one({"type": "info"})
            users = info["users"]
            # Register user
            if type == "register":
                r = get_user_info(client_socket)
                if r["name"] not in [x["name"] for x in users]:
                    users.append({"name": r["name"], "password": r["password"], "chatrooms":[],"invitations":[]})
                    col.update_one({"type": "info"}, {"$set": {"users": users}})
                    username = r["name"]
                    success = True
                else:
                    reason = "User with that name already exists"
                    print("User with that name already exists")
            elif type == "login":
                r = get_user_info(client_socket)
                if len([1 for x in users if x["password"]==r["password"] and x["name"]==x["name"]]):
                    username = r["name"]
                    success = True
                else:
                    reason = "Invalid credentials"
                    print("Invalid credentials")

                # if username is None:
                #     print("Username is None")
                #     continue

            # Loading chatrooms
            if success:
                ch_rooms = list(map(get_chatroom,[x["chatrooms"] for x in users if x["name"]==username][0]))
                inv1 = get_invites(username,"received")
                inv2 = get_invites(username,"sent")

                raw_data = {"success":success,"chatrooms":ch_rooms,"invitations":{"received":inv1,"sent":inv2}}
                # Add accepted socket to select.select() list
                sockets_list.append(client_socket)

                # Also save username and username header
                clients[client_socket] = {"data": username.encode()}
            else:
                raw_data = {"success":success,"response":reason}
            f = Fernet(fernet)
            cipher = f.encrypt(pickle.dumps(raw_data))
            message_header = f"{len(cipher):<{HEADER_LENGTH}}".encode()
            client_socket.send(b"3"+message_header+cipher)

            if debug_logger:
                print(f"\nConnection request received from {client_address}, username: {username if username is not None else 'None as connection was denied!'}")
                print(f"RSA key: {rsa_key}")
                print(f"Received fernet key: {fernet}")
                print(f"Sending saved messages ({len(cipher)} long): {cipher}")
                print(f"Success: {success}")
                if not success:
                    print(f"Reason: {reason}")
                print("\n")

        # Else existing socket is sending a message
        else:
            try:
                data = notified_socket.recv(TYPE_HEADER).decode()
            except:
                continue
            if not len(data):
                continue
            type = TYPES[int(data)]
            if type == "create_chatroom":
                length = int(notified_socket.recv(HEADER_LENGTH).decode().strip())
                s = notified_socket.recv(length)
                key = keys[notified_socket][1]
                f = Fernet(key.encode())
                msg = f.decrypt(s)
                kwargs = pickle.loads(msg)
                # params: {name, users, owner}
                raw_dict = create_chatroom(**kwargs)
                cipher = f.encrypt(pickle.dumps(raw_dict))
                notified_socket.send(b"4"+f"{len(cipher):<{HEADER_LENGTH}}".encode()+cipher)
                if debug_logger:
                    print(f'\nReceived action request from \"{clients[notified_socket]["data"].decode()}\"')
                    print(
                        f"- Type: {type}\n- Serialized message: {msg}")
                    print(f"- Decryption key: {key}")
                    print(f"- Encrypted message: {s.decode()}\n- Length: {length}")
            elif type == "get":
                # Modes:
                # - 0: get chatroom
                # - 1: get messages
                length = int(notified_socket.recv(HEADER_LENGTH).decode().strip())
                s = notified_socket.recv(length)
                key = keys[notified_socket][1]
                f = Fernet(key.encode())
                msg = pickle.loads(f.decrypt(s))
                if msg["mode"] == "message":
                    room = get_chatroom(msg["chatroom"],msg_limit=None)
                    if msg["from"] < len(room["messages"]):
                        raw_dict = {"messages":room["messages"][::-1][msg["from"]:msg["from"]+msg["limit"]],"chatroom":msg["chatroom"]}
                        cipher = f.encrypt(pickle.dumps(raw_dict))
                        notified_socket.send(b"7" + f"{len(cipher):<{HEADER_LENGTH}}".encode() + cipher)
                        print("Updated messages")


                # params: {mode=message,from,limit}

            elif type == "invite":
                key = keys[notified_socket][1]
                f = Fernet(key.encode())
                length = int(notified_socket.recv(HEADER_LENGTH).decode().strip())
                cipher = notified_socket.recv(length)
                invitation = pickle.loads(f.decrypt(cipher))
                print(f"invitation:{invitation}")
                invitation = invite(**invitation)
                if invitation:
                    cipher = f.encrypt(pickle.dumps(("sent",invitation)))
                    h = f"{len(cipher):<{HEADER_LENGTH}}".encode()
                    print(h,len(h))
                    notified_socket.send(b"5" + h + cipher)
                    for client in clients:
                        if clients[client]["data"].decode() == invitation["name"]:
                            fernet2 = Fernet(keys[client][1].encode())
                            cipher = fernet2.encrypt(pickle.dumps(("received", invitation)))
                            client.send(b"5"+f"{len(cipher):<{HEADER_LENGTH}}".encode() + cipher)
            elif type == "edit":
                key = keys[notified_socket][1]
                f = Fernet(key.encode())
                length = int(notified_socket.recv(HEADER_LENGTH).decode().strip())
                cipher = notified_socket.recv(length)
                # {action:delete,type:invite,item:{chatroom,sender,name,time(?)}}
                raw_dict = pickle.loads(f.decrypt(cipher))
                if raw_dict["type"] == "invite":
                    invitation = raw_dict["item"]
                    name, chatroom, sender = invitation["name"], invitation["chatroom"], invitation["sender"]
                    if raw_dict["action"] == "delete":
                        success = delete_invite(**invitation)
                        print("DELETED AN INVITE",success)
                        if len(l := [x for x in clients if clients[x]["data"].decode() == sender]):
                            receiver_client = l[0]
                            dict_to_send = {"action": "delete_invite", "item": raw_dict["item"]}
                            receiver_fernet = Fernet(keys[receiver_client][1])
                            c = receiver_fernet.encrypt(pickle.dumps(dict_to_send))
                            receiver_client.send(b"6" + f"{len(c):<{HEADER_LENGTH}}".encode() + c)

                    elif raw_dict["action"] == "cancel":
                        success = delete_invite(**invitation)
                        print("DELETED AN INVITE", success)
                        if len(l := [x for x in clients if clients[x]["data"].decode() == name]):
                            receiver_client = l[0]
                            dict_to_send = {"action": "cancel_invite", "item": raw_dict["item"]}
                            receiver_fernet = Fernet(keys[receiver_client][1])
                            c = receiver_fernet.encrypt(pickle.dumps(dict_to_send))
                            receiver_client.send(b"6" + f"{len(c):<{HEADER_LENGTH}}".encode() + c)


                        #dict_to_send = {"action":"delete_invite","item":}
                    elif raw_dict["action"] == "accept":
                        #TODO
                        # done - accept invite,
                        # done - send back data about the chatroom
                        # update client gui done
                        # check if the invite exists idk


                        doc = col.find_one({"type": "chatrooms"})
                        user_doc = col.find_one({"type": "info"})
                        all_user = user_doc["users"]
                        rooms = doc["chatrooms"]
                        for i in rooms:
                            if i["id"] == chatroom:
                                if name in [x["name"] for x in i["invitations"]]:
                                    break
                        else:
                            print("BYEEEEEEE")
                            continue

                        for i in all_user:
                            if i["name"] == name:
                                i["chatrooms"].append(chatroom)
                                break
                        for i in rooms:
                            if i["id"] == chatroom:
                                i["users"].append(name)
                                break
                        col.update_one({"type": "info"}, {"$set": {"users": all_user}})
                        col.update_one({"type": "chatrooms"}, {"$set": {"chatrooms": rooms}})
                        success = delete_invite(**invitation)
                        dict = get_chatroom(chatroom)
                        cipher = f.encrypt(pickle.dumps(dict))
                        if success:
                            notified_socket.send(b"4"+f"{len(cipher):<{HEADER_LENGTH}}".encode() + cipher)

                        if len(l := [x for x in clients if clients[x]["data"].decode() == sender]):
                            receiver_client = l[0]
                            dict_to_send = {"action": "delete_invite", "item": raw_dict["item"]}
                            receiver_fernet = Fernet(keys[receiver_client][1])
                            c = receiver_fernet.encrypt(pickle.dumps(dict_to_send))
                            receiver_client.send(b"6" + f"{len(c):<{HEADER_LENGTH}}".encode() + c)







            elif type == "message":
                message_header = notified_socket.recv(HEADER_LENGTH)
                if not len(message_header):
                    print('\nClosed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

                    # Remove from list for socket.socket()
                    sockets_list.remove(notified_socket)

                    # Remove from our list of users
                    del clients[notified_socket]

                    continue
                message_length = int(message_header.decode('utf-8').strip())
                raw_msg = notified_socket.recv(message_length)

                # Get user by notified socket, so we will know who sent the message
                user = clients[notified_socket]
                key = keys[notified_socket][1]
                f = Fernet(key.encode())
                # message format: {chatroom: id, sender: name ?, content: message}
                msg_dir = pickle.loads(f.decrypt(raw_msg))
                msg = msg_dir["content"]
                room = get_chatroom(msg_dir["chatroom"])
                if room is None:
                    print(f"Couldn't find room {msg_dir['chatroom']}")
                    continue
                upload_message(msg_dir["chatroom"],msg,user["data"].decode())
                online = [x for x in clients.values() if x in room["users"]]
                if debug_logger:
                    print(f'\nReceived message from user \"{user["data"].decode()}\"')
                    print(
                        f"- Encrypted message: {raw_msg.decode()}\n- Length: {message_length}")
                    print(f"- Decryption key: {key}")
                    print(f"- Plain text: {msg}")
                print(f"\nForwarding message to {len(room['users']) - 1} user in the chatroom ({len(online)} online)")
                # Iterate over connected clients and broadcast message

                for client_socket in clients:
                    if client_socket != notified_socket:
                        if clients[client_socket]["data"].decode() in room["users"]:
                            key = keys[client_socket][1]
                            f = Fernet(key)
                            msg_dir_out = {"content": msg, "sender": user['data'].decode(), "chatroom": room["id"]}
                            cipher = f.encrypt(pickle.dumps(msg_dir_out))
                            message_header = f"{len(cipher):<{HEADER_LENGTH}}".encode()
                            user_name = f"{user['data'].decode():<10}".encode()
                            if debug_logger:
                                print(f"- Sending message to user: {clients[client_socket]['data'].decode()}")
                                print(f"    * Encryption key: {key}")
                                print(f"    * Encrypted message: {cipher.decode()}\n    * Length: {message_header.decode()}")
                            # Send msg_dir cointaining chatroom, sender, message with header
                            if len(str(len(cipher))) < HEADER_LENGTH:
                                try:
                                    client_socket.send(b"1"+message_header+cipher)
                                except Exception as ex:
                                    print(f"Seems like {user_name.decode().strip()} disconnected!")
                                    exception_sockets.append(client_socket)
                                    continue
                            else:
                                print("The message is too long")
    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        print("Removed a socket")
        del clients[notified_socket]
