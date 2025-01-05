import socket
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Generate a new ECDH key pair for the server 
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Serialize public key to send to the client
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize the client's public key
def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

# Encrypt data using AES-GCM
def encrypt_data(key, data):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return nonce + encryptor.tag + encrypted_data

# Decrypt data using AES-GCM
def decrypt_data(key, encrypted_data):
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Handle client connection
def handle_client(client_socket):
    print(f"Connection from {client_socket.getpeername()}")
    
    # Send server's public key
    client_socket.send(serialize_public_key(public_key))

    # Receive client's public key
    client_public_key_pem = client_socket.recv(1024)
    client_public_key = deserialize_public_key(client_public_key_pem)

    # Generate shared key
    shared_secret = private_key.exchange(ec.ECDH(), client_public_key)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt',
        iterations=100000,
    ).derive(shared_secret)
    
    #print("Key exchange successful")

    # Receive encrypted request
    encrypted_request = client_socket.recv(4096)
    print(f"Encrypted request from client: {encrypted_request}")

    decrypted_request = decrypt_data(key, encrypted_request).decode()
    print(f"Decrypted request from client: {decrypted_request}")

    # Fetch the actual content
    response = requests.get(decrypted_request)

    # Encrypt and send the response
    encrypted_response = encrypt_data(key, response.url.encode())
    client_socket.send(encrypted_response)

    client_socket.close()

# Server setup
def start_server(host='0.0.0.0', port=8000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()
