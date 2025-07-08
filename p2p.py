import cmd
import threading
import socket
import json
import os
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoHandler:
    def __init__(self, password):
        # Generate a key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'static_salt',  # In production, use a random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

    def encrypt_data(self, data):
        if isinstance(data, str):
            data = data.encode()
        return self.cipher_suite.encrypt(data)

    def decrypt_data(self, encrypted_data):
        return self.cipher_suite.decrypt(encrypted_data)

    def encrypt_json(self, data):
        json_str = json.dumps(data)
        encrypted = self.encrypt_data(json_str)
        return encrypted

    def decrypt_json(self, encrypted_data):
        decrypted = self.decrypt_data(encrypted_data)
        return json.loads(decrypted)

class Peer:
    def __init__(self, host, port, tracker_host, tracker_port, password):
        self.host = host
        self.port = port
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.files = {}
        self.peers = {}
        self.crypto = CryptoHandler(password)

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Peer listening on {self.host}:{self.port}")

        threading.Thread(target=self.handle_incoming_connections).start()
        threading.Thread(target=self.register_with_tracker).start()

    def handle_incoming_connections(self):
        while True:
            client, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_peer_request, args=(client,)).start()

    def handle_peer_request(self, client):
        try:
            # Receive encrypted request
            encrypted_request = client.recv(4096)
            request = self.crypto.decrypt_json(encrypted_request)

            if request['type'] == 'get_file_list':
                response = {'files': list(self.files.keys())}
                encrypted_response = self.crypto.encrypt_json(response)
                client.send(encrypted_response)

            elif request['type'] == 'get_file':
                filename = request['filename']
                if filename in self.files:
                    # Send file size first
                    file_size = os.path.getsize(filename)
                    size_info = self.crypto.encrypt_json({'size': file_size})
                    client.send(size_info)

                    # Wait for acknowledgment
                    client.recv(1024)

                    # Send encrypted file chunks
                    with open(filename, 'rb') as f:
                        while True:
                            chunk = f.read(8192)  # Read in 8KB chunks
                            if not chunk:
                                break
                            encrypted_chunk = self.crypto.encrypt_data(chunk)
                            # Send the length of the encrypted chunk first
                            client.send(len(encrypted_chunk).to_bytes(8, byteorder='big'))
                            client.send(encrypted_chunk)
                else:
                    error_response = self.crypto.encrypt_json({'error': 'File not found'})
                    client.send(error_response)
        except Exception as e:
            print(f"Error handling peer request: {e}")
        finally:
            client.close()

    def register_with_tracker(self):
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.tracker_host, self.tracker_port))
                    message = {
                        'type': 'register',
                        'host': self.host,
                        'port': self.port,
                        'files': list(self.files.keys())
                    }
                    encrypted_message = self.crypto.encrypt_json(message)
                    s.send(encrypted_message)
            except Exception as e:
                print(f"Failed to register with tracker: {e}")
            time.sleep(10)

    def add_file(self, filename):
        if os.path.exists(filename):
            self.files[filename] = os.path.getsize(filename)
            print(f"Added {filename} to shared files")
        else:
            print(f"File {filename} does not exist")

    def search_file(self, filename):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.tracker_host, self.tracker_port))
            message = {'type': 'search', 'filename': filename}
            encrypted_message = self.crypto.encrypt_json(message)
            s.send(encrypted_message)
            
            encrypted_response = s.recv(4096)
            response = self.crypto.decrypt_json(encrypted_response)
            self.peers = response['peers']
            print(f"Peers with {filename}: {self.peers}")

    def download_file(self, filename):
        if not self.peers:
            print("No peers available. Search for the file first.")
            return

        for peer in self.peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer['host'], peer['port']))
                    
                    # Send encrypted request
                    request = {'type': 'get_file', 'filename': filename}
                    encrypted_request = self.crypto.encrypt_json(request)
                    s.send(encrypted_request)

                    # Receive encrypted size information
                    encrypted_size_info = s.recv(4096)
                    size_info = self.crypto.decrypt_json(encrypted_size_info)
                    
                    if 'error' in size_info:
                        print(f"Error: {size_info['error']}")
                        continue

                    # Send acknowledgment
                    s.send(b'ready')

                    # Receive and decrypt file in chunks
                    with open(f"downloaded_{filename}", 'wb') as f:
                        while True:
                            # Receive the length of the next encrypted chunk
                            chunk_len_bytes = s.recv(8)
                            if not chunk_len_bytes:
                                break
                            chunk_len = int.from_bytes(chunk_len_bytes, byteorder='big')
                            
                            # Receive the encrypted chunk
                            encrypted_chunk = s.recv(chunk_len)
                            if not encrypted_chunk:
                                break
                            
                            # Decrypt and write the chunk
                            decrypted_chunk = self.crypto.decrypt_data(encrypted_chunk)
                            f.write(decrypted_chunk)

                print(f"Downloaded {filename} from {peer['host']}:{peer['port']}")
                self.add_file(f"downloaded_{filename}")
                return
            except Exception as e:
                print(f"Failed to download from {peer['host']}:{peer['port']}: {e}")
        print("Failed to download file from any peer.")

class Tracker:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.peers = {}
        self.crypto = CryptoHandler(password)

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"Tracker listening on {self.host}:{self.port}")

        while True:
            client, addr = server.accept()
            threading.Thread(target=self.handle_request, args=(client,)).start()

    def handle_request(self, client):
        try:
            encrypted_request = client.recv(4096)
            request = self.crypto.decrypt_json(encrypted_request)

            if request['type'] == 'register':
                self.peers[f"{request['host']}:{request['port']}"] = {
                    'host': request['host'],
                    'port': request['port'],
                    'files': request['files']
                }
                print(f"Registered peer {request['host']}:{request['port']}")

            elif request['type'] == 'search':
                filename = request['filename']
                matching_peers = [
                    {'host': peer['host'], 'port': peer['port']}
                    for peer in self.peers.values()
                    if filename in peer['files']
                ]
                response = {'peers': matching_peers}
                encrypted_response = self.crypto.encrypt_json(response)
                client.send(encrypted_response)

            elif request['type'] == 'get_all_files':
                all_files = {f"{peer['host']}:{peer['port']}": peer['files'] 
                           for peer in self.peers.values()}
                response = {'all_files': all_files}
                encrypted_response = self.crypto.encrypt_json(response)
                client.send(encrypted_response)

        except Exception as e:
            print(f"Error handling request: {e}")
        finally:
            client.close()

class PeerCLI(cmd.Cmd):
    prompt = 'P2P> '

    def __init__(self, peer):
        super().__init__()
        self.peer = peer

    def do_add(self, filename):
        """Add a file to share: add <filename>"""
        self.peer.add_file(filename)

    def do_search(self, filename):
        """Search for a file: search <filename>"""
        self.peer.search_file(filename)

    def do_download(self, filename):
        """Download a file: download <filename>"""
        self.peer.download_file(filename)

    def do_list(self, arg):
        """List all shared files by this peer"""
        for filename, size in self.peer.files.items():
            print(f"{filename} - Size: {size} bytes")

    def do_all_files(self, arg):
        """List all shared files by all peers"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.peer.tracker_host, self.peer.tracker_port))
            message = {'type': 'get_all_files'}
            encrypted_message = self.peer.crypto.encrypt_json(message)
            s.send(encrypted_message)
            
            encrypted_response = s.recv(4096)
            response = self.peer.crypto.decrypt_json(encrypted_response)
            all_files = response['all_files']
            print("All shared files across peers:")
            for peer, files in all_files.items():
                print(f"Peer {peer} has shared files: {files}")

    def do_peers(self, arg):
        """List all known peers"""
        for peer in self.peer.peers:
            print(f"{peer['host']}:{peer['port']}")

    def do_quit(self, arg):
        """Quit the program"""
        print("Quitting...")
        return True

    def do_help(self, arg):
        """List available commands with "help" or detailed help with "help cmd"."""
        super().do_help(arg)

def start_peer_cli(peer):
    cli = PeerCLI(peer)
    cli.cmdloop("Welcome to the P2P File Sharing System. Type 'help' for commands.")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error getting local IP: {e}")
        ip = 'localhost'
    return ip

if __name__ == "__main__":
    tracker_host = 'localhost'
    tracker_port = 9000
    password = input("Enter encryption password: ")  # Same password must be used for all peers

    choice = input("Run as (t)racker or (p)eer? ")

    if choice.lower() == 't':
        tracker_host = get_local_ip()
        tracker = Tracker(tracker_host, tracker_port, password)
        tracker.start()

    elif choice.lower() == 'p':
        tracker_host = input("Enter tracker host (default: localhost): ") or 'localhost'
        peer_host = get_local_ip()
        peer_port = int(input("Enter peer port: "))
        peer = Peer(peer_host, peer_port, tracker_host, tracker_port, password)

        peer_thread = threading.Thread(target=peer.start)
        peer_thread.start()

        start_peer_cli(peer)

        peer_thread.join()

    else:
        print("Invalid choice. Exiting.")