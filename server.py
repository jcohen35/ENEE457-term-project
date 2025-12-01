import socket
import threading
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

# RSA KEY GENERATION (SERVER)
rsa_key = RSA.generate(2048)
private_key = rsa_key
public_key = rsa_key.publickey()

print("Server RSA keys generated.")

# Each client: {'socket', 'aes_key', 'aes_nonce', 'public_key'}
clients = []
MAX_CLIENTS = 5
lock = threading.Lock()   # to protect clients list


def relay_messages(index):
    """
    Receive signed+encrypted messages from one client,
    verify signature, then re-encrypt and forward to all others.
    """
    while True:
        with lock:
            if index >= len(clients):
                return
            client_info = clients[index]
        client_sock = client_info['socket']
        aes_key = client_info['aes_key']
        aes_nonce = client_info['aes_nonce']
        client_pub = client_info['public_key']

        try:
            data = client_sock.recv(4096)
            if not data:
                print(f"Client {index+1} disconnected.")
                with lock:
                    try:
                        client_sock.close()
                    except:
                        pass
                return

            try:
                data_lst = data.split(b'||')
            except ValueError:
                print("Received malformed packet from client", index + 1)
                continue

            if len(data_lst) == 3: # for normal message
                sig_b64, enc_b64, name_b64 = data_lst

                # Decode signature and AES ciphertext+tag
                try:
                    sig = base64.b64decode(sig_b64)
                    enc = base64.b64decode(enc_b64)
                except Exception:
                    print("Base64 decode error from client", index + 1)
                    continue

                # Split ciphertext and tag (last 16 bytes = tag)
                ciphertext = enc[:-16]
                tag = enc[-16:]

                # Decrypt with this client's AES key
                try:
                    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=aes_nonce)
                    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
                except Exception:
                    print("AES decrypt/tag verify FAILED from client", index + 1)
                    continue

                # Verify signature over the plaintext
                h = SHA256.new(plaintext)
                verifier = PKCS1_v1_5.new(client_pub)
                try:
                    verifier.verify(h, sig)
                except (ValueError, TypeError):
                    print("Signature verification FAILED from client", index + 1)
                    continue

                print(f"Verified message from client {index + 1}: {plaintext.decode('utf-8', errors='ignore')}")

                # Forward plaintext to all OTHER clients that are connected
                with lock:
                    for j, other in enumerate(clients):
                        if j == index:
                            continue
                        other_sock = other['socket']
                        other_key = other['aes_key']
                        other_nonce = other['aes_nonce']

                        try:
                            out_cipher = AES.new(other_key, AES.MODE_EAX, nonce=other_nonce)
                            out_ct, out_tag = out_cipher.encrypt_and_digest(plaintext)
                            out_enc_b64 = base64.b64encode(out_ct + out_tag)
                            # NOTE: we forward ONLY encrypted message (no sig) –
                            # clients just decrypt and print.
                            packet = b'||'.join([
                                b'',             
                                out_enc_b64,    
                                name_b64
                            ])
                            other_sock.send(packet)
                        except Exception:
                            # ignore failed send to that client
                            pass

            elif len(data_lst) == 4: # for file
                fsig_b64, fname_b64, fenc_b64, name_b64 = data_lst

                 # Decode signature and AES ciphertext+tag
                try:
                    fsig = base64.b64decode(fsig_b64)
                    fenc = base64.b64decode(fenc_b64)
                    fname = fname_b64.decode()
                except Exception:
                    print("Base64 file decode error from client", index + 1)
                    continue

                # Split ciphertext and tag (last 16 bytes = tag)
                ciphertext = fenc[:-16]
                tag = fenc[-16:]

                # Decrypt with this client's AES key
                try:
                    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=aes_nonce)
                    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
                except Exception:
                    print("AES decrypt/tag verify FAILED from client", index + 1)
                    continue

                # Verify signature over the plaintext
                h = SHA256.new(plaintext)
                verifier = PKCS1_v1_5.new(client_pub)
                try:
                    verifier.verify(h, fsig)
                except (ValueError, TypeError):
                    print("Signature verification FAILED from client", index + 1)
                    continue

                print(f"Verified message from client {index + 1}: {fname}")

                # Forward plaintext to all OTHER clients that are connected
                with lock:
                    for j, other in enumerate(clients):
                        if j == index:
                            continue
                        other_sock = other['socket']
                        other_key = other['aes_key']
                        other_nonce = other['aes_nonce']

                        try:
                            out_cipher = AES.new(other_key, AES.MODE_EAX, nonce=other_nonce)
                            out_ct, out_tag = out_cipher.encrypt_and_digest(plaintext)
                            out_enc_b64 = base64.b64encode(out_ct + out_tag)
                            # NOTE: we forward ONLY encrypted message (no sig) –
                            # clients just decrypt and print.
                            packet = b'||'.join([
                                b'',
                                fname_b64,             
                                out_enc_b64,    
                                name_b64
                            ])
                            other_sock.send(packet)
                        except Exception:
                            # ignore failed send to that client
                            pass
            else:
                print("\nMalformed packet received")

        except Exception:
            print(f"Error in relay thread for client {index+1}")
            return


def handle_handshake(client_socket):
    # Send server public key
    client_socket.send(public_key.export_key())

    # Receive CLIENT public key
    client_pub_data = client_socket.recv(4096)
    if not client_pub_data:
        return None, None, None, None
    client_public_key = RSA.import_key(client_pub_data)

    # Receive encrypted AES key info
    encrypted_data = client_socket.recv(4096)
    if not encrypted_data:
        return None, None, None, None

    rsa_cipher = PKCS1_OAEP.new(private_key)
    decrypted = rsa_cipher.decrypt(encrypted_data)

    # decrypted = AES_key (16 bytes) + nonce (16 bytes)
    aes_key = decrypted[:16]
    aes_nonce = decrypted[16:32]

    print("Handshake complete: AES key and nonce received from client.")
    return client_public_key, aes_key, aes_nonce, None
# SERVER SETUP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 9999
server.bind(('', port))
server.listen(MAX_CLIENTS)

print(f"Server listening on port {port}, up to {MAX_CLIENTS} clients...\n")
print(server.getsockname())

def accept_loop():
    while True:
        client_sock, addr = server.accept()
        with lock:
            if len(clients) >= MAX_CLIENTS:
                print("Max clients reached, rejecting new connection from", addr)
                client_sock.close()
                continue

        print(f"New client connected from {addr}")

        client_pub, aes_k, aes_n, client_name = handle_handshake(client_sock)
        if client_pub is None:
            print("Handshake failed; closing client.")
            client_sock.close()
            continue

        with lock:
            index = len(clients)
            clients.append({
                'socket': client_sock,
                'aes_key': aes_k,
                'aes_nonce': aes_n,
                'public_key': client_pub
            })

        print(f"Client {index+1} fully registered. Total clients: {len(clients)}")

        # Start a relay thread for THIS client immediately
        threading.Thread(target=relay_messages, args=(index,), daemon=True).start()


# Start accepting clients
accept_thread = threading.Thread(target=accept_loop, daemon=True)
accept_thread.start()

# Keep server main thread alive
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\nServer shutting down...")
    server.close()