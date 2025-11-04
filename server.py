import socket
import threading

#prints incoming messages when they get recieved
def listen(c):
    while True:
        msg = c.recv(1024)
        if msg:
            print(f"\033[0;32mRecieved: \033[0;33m{msg.decode()}\033[0;1m")

#sends messages
def send(c):
    while True:
        msg = input()
        c.send(msg.encode())
 

# take the server name and port name
host = 'local host'
port = 5000
 
# create a socket at server side
# using TCP / IP protocol
s = socket.socket(socket.AF_INET, 
                  socket.SOCK_STREAM)
 
# bind the socket with server
# and port number
s.bind(('', port))
 
# allow maximum 1 connection to
# the socket
s.listen(1)
 
# wait till a client accept
# connection
c, addr = s.accept()
 
# display client address
print("CONNECTION FROM:", str(addr))

print("Send and Recieve Messages Below:")
print("\033[0;31m")

#create and join a sending and recieving thread
listen_thread = threading.Thread(target=listen, args = (c,))
send_thread = send_thread = threading.Thread(target=send, args = (c,))
listen_thread.start()
send_thread.start()
listen_thread.join()
send_thread.join()

# disconnect the server
c.close()
print("closed")

