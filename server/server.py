# server.py

import socket
import threading
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

SERVER_HOST = 'localhost'
SERVER_PORT = 12345

def handle_client(client_socket):
    try:
        # Step 1: Receive ClientHello
        data = client_socket.recv(8192).decode()
        lines = data.split('\n')

        # Extract MessageType
        if lines[0].startswith('MessageType='):
            message_type = lines[0][len('MessageType='):].strip()
        else:
            raise Exception("Invalid MessageType line")

        if message_type != 'ClientHello':
            raise Exception("Invalid MessageType")

        # Extract Certificate
        certificate_line_index = None
        for idx, line in enumerate(lines):
            if line.startswith('Certificate='):
                certificate_line_index = idx
                break

        if certificate_line_index is not None:
            # Remove 'Certificate=' from the beginning
            first_cert_line = lines[certificate_line_index][len('Certificate='):]
            # Get all subsequent lines to reconstruct the certificate
            certificate_lines = [first_cert_line] + lines[certificate_line_index + 1:]
            client_cert_str = '\n'.join(certificate_lines).strip()
        else:
            raise Exception("Certificate not found")

        # Step 2: Server Verifies Client Certificate
        client_cert = x509.load_pem_x509_certificate(
            client_cert_str.encode(), default_backend()
        )

        # Load CA certificate
        with open('../ca/certs/ca.cert.pem', 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Verify client certificate is signed by the CA
        ca_public_key = ca_cert.public_key()
        try:
            ca_public_key.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )
            print("Client certificate verified successfully.")
        except Exception as e:
            raise Exception("Failed to verify client certificate: " + str(e))

        # Step 3: Send ServerHello
        with open('server.cert.pem', 'r') as f:
            server_cert_str = f.read()

        server_hello = f"MessageType=ServerHello\nCertificate={server_cert_str}"
        client_socket.sendall(server_hello.encode())

        # Step 4: Wait for client's forward request
        data = client_socket.recv(1024).decode()
        lines = data.split('\n')
        if lines[0].startswith('MessageType='):
            message_type = lines[0][len('MessageType='):].strip()
        else:
            raise Exception("Invalid MessageType line")

        if message_type != 'forward':
            raise Exception("Invalid MessageType")

        target_host = ''
        target_port = 0
        for line in lines[1:]:
            if line.startswith('TargetHost='):
                target_host = line[len('TargetHost='):].strip()
            elif line.startswith('TargetPort='):
                target_port = int(line[len('TargetPort='):].strip())

        if not target_host or not target_port:
            raise Exception("TargetHost or TargetPort not specified")

        # Step 6: Server agrees and sets up session
        # Generate Session Key & IV
        session_key = os.urandom(32)  # AES-256 key
        session_iv = os.urandom(16)   # AES CTR IV

        # Encrypt Session Key & IV with client's public key
        client_public_key = client_cert.public_key()
        encrypted_session_key = client_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_session_iv = client_public_key.encrypt(
            session_iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Create socket endpoint for session communication
        SESSION_PORT = 12346  # Or dynamically select an available port

        # Step 7: Send session message to client
        session_message = (
            f"MessageType=session\n"
            f"SessionKey={encrypted_session_key.hex()}\n"
            f"SessionIV={encrypted_session_iv.hex()}\n"
            f"ServerHost={SERVER_HOST}\n"
            f"ServerPort={SESSION_PORT}"
        )
        client_socket.sendall(session_message.encode())

        # Step 10: Set up secure communication channel
        threading.Thread(
            target=session_handler,
            args=(session_key, session_iv, target_host, target_port, SESSION_PORT)
        ).start()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def session_handler(session_key, session_iv, target_host, target_port, session_port):
    # Set up session socket
    session_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    session_socket.bind((SERVER_HOST, session_port))
    session_socket.listen(1)
    conn, _ = session_socket.accept()

    # Connect to target host and port
    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_socket.connect((target_host, target_port))

    # Set up AES encryption/decryption
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(
        algorithms.AES(session_key),
        modes.CTR(session_iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # Start forwarding threads
    threading.Thread(target=forward, args=(conn, target_socket, decryptor)).start()
    threading.Thread(target=forward, args=(target_socket, conn, encryptor)).start()

def forward(src_socket, dst_socket, transformer):
    try:
        while True:
            data = src_socket.recv(4096)
            if not data:
                break
            transformed_data = transformer.update(data)
            dst_socket.sendall(transformed_data)
    except Exception as e:
        print(f"Forwarding error: {e}")
    finally:
        src_socket.close()
        dst_socket.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_sock, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_sock,)).start()

if __name__ == "__main__":
    main()

