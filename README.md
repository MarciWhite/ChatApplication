# ChatApplication
A chat application with some basic security features. It was made before I started college as a solo project, that's why there is a lack of documentation.

## DISCLAIMER
THIS IS IN NO WAY SECURE, NEVER TRY TO IMPLEMENT YOUR OWN CRYPTO. THIS WAS DONE FOR EDUCATIONAL PURPOSES, WHERE SECURITY WAS NOT A PRIORITY.

## Libraries used
- pymongo - database connection
- socket - server-client connection
- pickle - converting dictionaries to bytes that can be sent through sockets
- tkinter - user interface, used with threading so it doesn't block the socket connection
- sv_ttk - grants a modern look to the tkinter, purely aestethic
- cryptography - symmetric key, used after key exchange
## Security
This project isn't cryptographically secure, it's vulnerable to a lot of attacks and the messages aren't verified. The goal of this project was to deepen my understanding of sockets and basic cryptographic algorithms. The app uses a self implemented version of RSA for key exchange. And then fernet as symmetric key from pythons cryptography library. In a later version the passwords were stored hashed with salt, sadly I couldn't find that version.

## Features
You can create chatrooms after logging in/registering as a new user, the username must be unique. You can send invitations to a chatroom through the GUI, then these can be accepted or declined by the recipient. Every data (chatrooms, messages, users) are stored in a mongodb database. If the server recieves a message, it updates the databse and sends it to currently online users that are in the affected chatroom, the the client recieves the message and updates the GUI accordingly.


