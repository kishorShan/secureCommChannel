# client.py

import socket
import threading
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

SERVER_HOST = 'localhost'
SERVER_PORT = 12345

def main():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        # Step 1: Send ClientHello
        with open('client.cert.pem', 'r') as f:
            client_cert_str = f.read()

        client_hello = f"MessageType=ClientHello\nCertificate={client_cert_str}"
        client_socket.sendall(client_hello.encode())

        # Step 4: Receive ServerHello
        data = client_socket.recv(8192).decode()
        lines = data.split('\n')

        # Extract MessageType
        if lines[0].startswith('MessageType='):
            message_type = lines[0][len('MessageType='):].strip()
        else:
            raise Exception("Invalid MessageType line")

        if message_type != 'ServerHello':
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
            server_cert_str = '\n'.join(certificate_lines).strip()
        else:
            raise Exception("Certificate not found")

        # Step 5: Verify server certificate
        server_cert = x509.load_pem_x509_certificate(
            server_cert_str.encode(), default_backend()
        )

        # Load CA certificate
        with open('../ca/certs/ca.cert.pem', 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Verify server certificate is signed by the CA
        ca_public_key = ca_cert.public_key()
        try:
            ca_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm,
            )
            print("Server certificate verified successfully.")
        except Exception as e:
            raise Exception("Failed to verify server certificate: " + str(e))

        # Step 5: Request port forwarding
        forward_request = (
            f"MessageType=forward\n"
            f"TargetHost=localhost\n"
            f"TargetPort=6789"
        )
        client_socket.sendall(forward_request.encode())

        # Step 8: Receive session message
        data = client_socket.recv(8192).decode()
        lines = data.split('\n')

        # Extract MessageType
        if lines[0].startswith('MessageType='):
            message_type = lines[0][len('MessageType='):].strip()
        else:
            raise Exception("Invalid MessageType line")

        if message_type != 'session':
            raise Exception("Invalid MessageType")

        # Extract SessionKey, SessionIV, ServerHost, ServerPort
        encrypted_session_key_hex = ''
        encrypted_session_iv_hex = ''
        server_host = ''
        server_port = 0
        for line in lines[1:]:
            if line.startswith('SessionKey='):
                encrypted_session_key_hex = line[len('SessionKey='):].strip()
            elif line.startswith('SessionIV='):
                encrypted_session_iv_hex = line[len('SessionIV='):].strip()
            elif line.startswith('ServerHost='):
                server_host = line[len('ServerHost='):].strip()
            elif line.startswith('ServerPort='):
                server_port = int(line[len('ServerPort='):].strip())

        if not encrypted_session_key_hex or not encrypted_session_iv_hex or not server_host or not server_port:
            raise Exception("Incomplete session message")

        # Step 8: Decrypt Session Key & IV
        with open('client.key.pem', 'rb') as f:
            client_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        encrypted_session_key = bytes.fromhex(encrypted_session_key_hex)
        encrypted_session_iv = bytes.fromhex(encrypted_session_iv_hex)

        session_key = client_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        session_iv = client_private_key.decrypt(
            encrypted_session_iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Step 9: VPN client connects with user
        # Set up connection to the session host and port
        session_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        session_socket.connect((server_host, server_port))

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
        threading.Thread(target=forward_input, args=(session_socket, encryptor)).start()
        threading.Thread(target=forward_output, args=(session_socket, decryptor)).start()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def forward_input(session_socket, encryptor):
    try:
        while True:
            data = input()
            encrypted_data = encryptor.update(data.encode() + b'\n')
            session_socket.sendall(encrypted_data)
    except Exception as e:
        print(f"Input Error: {e}")
    finally:
        session_socket.close()

def forward_output(session_socket, decryptor):
    try:
        while True:
            data = session_socket.recv(4096)
            if not data:
                break
            decrypted_data = decryptor.update(data)
            print(decrypted_data.decode(), end='')
    except Exception as e:
        print(f"Output Error: {e}")
    finally:
        session_socket.close()

if __name__ == "__main__":
        main()

