import socket
import threading
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_v1_5

# CLIENT CONNECTS TO SERVER
server_ip = input("Enter server IP: ")  # IPv4 address
client_name = input("Enter your name: ")
port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server_ip, port))

print("Connected to server. Starting RSA handshake...")

# RECEIVE SERVER PUBLIC KEY
public_key_data = s.recv(4096)
server_public_key = RSA.import_key(public_key_data)

# GENERATE AES KEY AND NONCE
aes_key = get_random_bytes(16)
aes_nonce = get_random_bytes(16)

# GENERATE CLIENT'S KEYPAIR
key = RSA.generate(2048)
Client_private_key = key 
Client_public_key = key.publickey()

# send client public key to server so it can verify signatures
s.send(Client_public_key.export_key())

# SEND AES KEY + NONCE ENCRYPTED WITH RSA
rsa_cipher = PKCS1_OAEP.new(server_public_key)
payload = aes_key + aes_nonce
encrypted_payload = rsa_cipher.encrypt(payload)
s.send(encrypted_payload)

print("AES key and nonce sent to server.\nEncrypted chat ready.")

# CREATE AES CIPHER HELPERS
def encrypt_message(msg):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=aes_nonce)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(ciphertext + tag)

def decrypt_message(data):
    data = base64.b64decode(data)
    ciphertext = data[:-16]
    tag = data[-16:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=aes_nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# SIGNING (CLIENT SIDE)
def signature(data_bytes):
    h = SHA256.new(data_bytes)
    signer = PKCS1_v1_5.new(Client_private_key)
    return signer.sign(h)


# client-side verification
def check_signature(data_bytes, sig_bytes, sender_public_key):
    h = SHA256.new(data_bytes)
    verifier = PKCS1_v1_5.new(sender_public_key)
    try:
        verifier.verify(h, sig_bytes)
        return True
    except (ValueError, TypeError):
        return False

# LISTEN THREAD
def listen():
    while True:
        try:
            data = s.recv(4096)
            if data:
                try:
                    parts = data.split(b'||')

                    if len(parts) == 3: # recieved a string
                        _, enc_b64, name_b64 = parts
                        msg = decrypt_message(enc_b64)
                        sender = name_b64.decode()
                        print(f"\n{sender}: {msg}")
                    elif len(parts) == 4: # recieved a file
                        _, fname_b64, enc_content_b64, name_b64 = parts
                        content = decrypt_message(enc_content_b64)
                        sender = name_b64.decode()
                        fname = fname_b64.decode()

                        # create file and write contents
                        with open(fname, 'w') as f:
                            f.write(content)

                        print(f"\n{sender}: {fname}")
                    else:
                        print("Malformed packet received")
                        continue
                except ValueError:
                    print("\n[Malformed packet received]")

                except Exception:
                    print("\n[Error decrypting message]")
        except:
            break

# SEND THREAD
def send():
    while True:
        msg = input()
        name = client_name.encode()

        # check if msg is a file
        try:
            file = open(msg, 'r')
            content = file.read()

            # encrypt the content of file and file name with AES
            encrypted = encrypt_message(content)
            fname_enc = msg.encode()

            # sign the contents of the file
            sig = signature(content.encode())
            sig_b64 = base64.b64encode(sig)

            packet = sig_b64 + b'||' + fname_enc + b'||' + encrypted + b'||' + name

            print("\nSending file...")

            file.close()

        except FileNotFoundError:
            # encrypt the message with AES
            encrypted = encrypt_message(msg)

            # sign the plaintext message
            sig = signature(msg.encode())
            sig_b64 = base64.b64encode(sig)

            packet = sig_b64 + b'||' + encrypted + b'||' + name

        s.send(packet)

# Start both threads
t_listen = threading.Thread(target=listen)
t_send = threading.Thread(target=send)

t_listen.start()
t_send.start()
