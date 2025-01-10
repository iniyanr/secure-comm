import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint
from Crypto.Hash import SHA256

PRIME = 23
BASE = 5
BLOCK_SIZE = 16

def generate_dh_keys():
    private_key = randint(1, PRIME - 1)
    public_key = pow(BASE, private_key, PRIME)
    return private_key, public_key

def compute_shared_key(their_public_key, private_key):
    shared_key = pow(their_public_key, private_key, PRIME)
    return hashlib.sha256(str(shared_key).encode()).digest()[:16]

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))
    return cipher.iv + ciphertext

def decrypt_message(key, data):
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE).decode()

def generate_message_hash(message):
    return SHA256.new(message.encode()).hexdigest()

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 65432))

    private_key, public_key = generate_dh_keys()
    their_public_key = int(client_socket.recv(1024).decode())
    client_socket.send(str(public_key).encode())
    session_key = compute_shared_key(their_public_key, private_key)

    while True:
        message = input("Client: ")
        message_hash = generate_message_hash(message)
        encrypted_message = encrypt_message(session_key, message + "||" + message_hash)
        client_socket.send(encrypted_message)

        encrypted_response = client_socket.recv(1024)
        if not encrypted_response:
            break

        decrypted_response = decrypt_message(session_key, encrypted_response)
        response, received_hash = decrypted_response.rsplit("||", 1)

        if generate_message_hash(response) == received_hash:
            print(f"Server: {response}")
        else:
            print("Response integrity compromised!")

    client_socket.close()

if __name__ == "__main__":
    client_program()

