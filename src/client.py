import socket
import threading
 
def listen(c):
    while True:
        msg = c.recv(1024)
        if msg:
            print(f"\033[0;32mRecieved: \033[0;33m{msg.decode()}\033[0;1m")


def send(c):
    while True:
        msg = input()
        c.send(msg.encode())


# take the server name and port name
 
host = 'local host'
port = 5000
 
# create a socket at client side
# using TCP / IP protocol
s = socket.socket(socket.AF_INET,
                  socket.SOCK_STREAM)
 
# connect it to server and port 
# number on local computer.
s.connect(('127.0.0.1', port))

print("Send and Recieve Messages Below:")

listen_thread = threading.Thread(target=listen, args = (s,))
send_thread = send_thread = threading.Thread(target=send, args = (s,))
listen_thread.start()
send_thread.start()
listen_thread.join()
send_thread.join()
# disconnect the client
s.close()
print("socket closed")
