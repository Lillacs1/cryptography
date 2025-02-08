import socket
import threading
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

#  shared secret
SHARED_SECRET = b'HWIDEIDEOEIFWJRFIROPG3R8035-T035OT-53TG054GK[45GOWPJTGOEIJGTEOGJETGOETPGJHETU9T'

#  256-bit key (32 bytes) using PBKDF2
def derive_key(shared_secret):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        # OKAY HERE I USED A CONSTANT a constant salt for simplicity
        salt=b'hrifbwofbwruipwueriofijregerpg99gre9g8g3ghy8gjrbfg7tcr0wfgherg30-t9358t3783nf8wrgfew7frgwtfwe9yfw',  
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

# AES encryption
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
   
    print(f"\n[Encryption] tHE Original Message: {message}")
    print(f"[Encryption] THE Padded Message: {padded_message}")
    print(f"[Encryption] THE Encrypted Message (Base64): {base64.b64encode(iv + ciphertext).decode()}")
    
    return base64.b64encode(iv + ciphertext).decode()

# the AES decryption processes
def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    message = unpadder.update(padded_message) + unpadder.finalize()
    
    #  decryption process i useing logs
    print(f"\n[Decryption] Encrypted Message: {base64.b64encode(iv + ciphertext).decode()}")
    print(f"[Decryption] Padded Message: {padded_message}")
    print(f"[Decryption] Original Message: {message.decode()}")
    
    return message

#  each client connection from alias
def client_handler(client_socket, addr, clients, shared_key):
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            message = message.decode()
            parsed_message = json.loads(message)
            
            if parsed_message['cmd'] == 'MESG':
                print(f"\n[Server] I have Received an  encrypted message from {parsed_message['name']}")
                decrypted_message = decrypt_message(parsed_message['mesg'], shared_key).decode()
                print(f"[Server] {parsed_message['name']} says: {decrypted_message}")
                
                # show the message to all clients
                for client in clients:
                    encrypted_message = encrypt_message(decrypted_message, shared_key)
                    client.send(json.dumps({
                        'cmd': 'MESG',
                        'name': parsed_message['name'],
                        'mesg': encrypted_message
                    }).encode())
        
        except Exception as e:
            print(f"An error !!!!!!!!!Error: {e}")
            clients.remove(client_socket)
            client_socket.close()
            break

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9999))
    server.listen(5)
    print("the made Server listening on port 9999")

    shared_key = derive_key(SHARED_SECRET)
    clients = []

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        print(f"a new Client has connected from {addr}")
        
       
        threading.Thread(target=client_handler, args=(client_socket, addr, clients, shared_key)).start()

if __name__ == "__main__":
    main()
