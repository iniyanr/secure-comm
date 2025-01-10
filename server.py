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

def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 65432))
    server_socket.listen(1)
    conn, address = server_socket.accept()

    private_key, public_key = generate_dh_keys()
    conn.send(str(public_key).encode())
    their_public_key = int(conn.recv(1024).decode())
    session_key = compute_shared_key(their_public_key, private_key)

    while True:
        encrypted_data = conn.recv(1024)
        if not encrypted_data:
            break

        decrypted_message = decrypt_message(session_key, encrypted_data)
        message, received_hash = decrypted_message.rsplit("||", 1)

        if generate_message_hash(message) == received_hash:
            print(f"Client: {message}")
        else:
            print("Message integrity compromised!")

        response = input("Server: ")
        response_hash = generate_message_hash(response)
        encrypted_response = encrypt_message(session_key, response + "||" + response_hash)
        conn.send(encrypted_response)

    conn.close()

if __name__ == "__main__":
    server_program()

