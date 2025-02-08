import socket
import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import threading


SHARED_SECRET = b'HWIDEIDEOEIFWJRFIROPG3R8035-T035OT-53TG054GK[45GOWPJTGOEIJGTEOGJETGOETPGJHETU9T'

# 256-bit key using PBKDF2
def derive_key(shared_secret):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=b'hrifbwofbwruipwueriofijregerpg99gre9g8g3ghy8gjrbfg7tcr0wfgherg30-t9358t3783nf8wrgfew7frgwtfwe9yfw',  
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

# A.E.S encryption and decryption
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(padded_message) + unpadder.finalize()

def receive_messages(client_socket, shared_key):
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                message = message.decode()
                parsed_message = json.loads(message)
                if parsed_message['cmd'] == 'MESG':
                    decrypted_message = decrypt_message(parsed_message['mesg'], shared_key)
                    print(f"{parsed_message['name']} has said: {decrypted_message.decode()}")
        except:
            print("//////////-----------the connection has been  closed by the server------------////////////////")
            break

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 9999))

    shared_key = derive_key(SHARED_SECRET)

    name = input("----------------HELLO kindly Enter your alias: ")

    
    threading.Thread(target=receive_messages, args=(client, shared_key)).start()

    
    client.send(json.dumps({'cmd': 'HELO', 'name': name}).encode())

    # Send  messages
    while True:
        message = input(f"{name}: ")
        encrypted_message = encrypt_message(message, shared_key)
        client.send(json.dumps({
            'cmd': 'MESG',
            'name': name,
            'mesg': encrypted_message
        }).encode())

if __name__ == "__main__":
    main()
