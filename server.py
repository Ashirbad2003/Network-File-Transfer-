import socket
import os
import threading # For multi-threading

# Configuration
HOST = '127.0.0.1'
PORT = 9999
SERVER_FILES_DIR = 'server_files'
BUFFER_SIZE = 5000

# Security 
USERS = {
    'user1': 'wipro123',
    'user2': 'wipro456',
    'user3': 'wipro789'
}

# Encryption
ENCRYPTION_KEY = 0xAF

def encrypt(data):
    return bytes([b ^ ENCRYPTION_KEY for b in data])

def decrypt(data):
    return bytes([b ^ ENCRYPTION_KEY for b in data])


print("Starting server...")

if not os.path.exists(SERVER_FILES_DIR):
    os.makedirs(SERVER_FILES_DIR)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5) # Can listen for 5 connections in the queue

print(f" Multi-threaded Secure Server is listening on {HOST}:{PORT}")

# Function to handle each client connection
def handle_client(conn, addr):
    """Handles a single client connection in its own thread."""
    
    print(f"New connection from {addr}. Waiting for authentication...")
    is_authenticated = False
    username = "unknown" # For logging
    
    # Main try-except block for client handling
    try:
        with conn:
            # Authentication Step 
            conn.sendall(encrypt("AUTH_REQUIRED".encode('utf-8')))
            raw_data = conn.recv(1024)
            if not raw_data:
                raise ConnectionError("Client disconnected before auth.")
                
            auth_str = decrypt(raw_data).decode('utf-8')
            
            if auth_str.startswith("AUTH:"):
                parts = auth_str.split(':', 2)
                username = parts[1]
                password = parts[2]
                
                if USERS.get(username) == password:
                    is_authenticated = True
                    conn.sendall(encrypt("AUTH_SUCCESS".encode('utf-8')))
                    print(f"User '{username}' from {addr} authenticated successfully.")
                else:
                    conn.sendall(encrypt("AUTH_FAILED".encode('utf-8')))
                    print(f"User '{username}' from {addr} failed authentication.")
            else:
                conn.sendall(encrypt("AUTH_FAILED".encode('utf-8')))
                print(f"Invalid auth attempt from {addr}.")
            
            if not is_authenticated:
                print(f"Disconnecting unauthenticated client {addr}.")
                return # Thread Ends here for unauthenticated clients

            # Main Loop (Only for authenticated users)
            while True:
                raw_data = conn.recv(1024)
                if not raw_data:
                    break 

                command_str = decrypt(raw_data).decode('utf-8')
                print(f"Received command from '{username}': {command_str}")

                if command_str == 'LIST':
                    # File LIST 
                    files = os.listdir(SERVER_FILES_DIR)
                    if not files: file_list_str = "No files found."
                    else: file_list_str = ",".join(files)
                    conn.sendall(encrypt(file_list_str.encode('utf-8')))

                elif command_str.startswith('DOWNLOAD:'):
                    # File DOWNLOAD 
                    filename = os.path.basename(command_str.split(':', 1)[1])
                    filepath = os.path.join(SERVER_FILES_DIR, filename)
                    if os.path.exists(filepath):
                        filesize = os.path.getsize(filepath)
                        conn.sendall(encrypt(f"OK:{filesize}".encode('utf-8')))
                        with open(filepath, 'rb') as f:
                            while True:
                                chunk = f.read(BUFFER_SIZE)
                                if not chunk: break
                                conn.sendall(encrypt(chunk))
                        print(f"Sent {filename} to '{username}'.")
                    else:
                        conn.sendall(encrypt("ERROR:File not found".encode('utf-8')))
                
                elif command_str.startswith('UPLOAD:'):
                    # File UPLOAD 
                    parts = command_str.split(':', 2)
                    filename = os.path.basename(parts[1])
                    filesize = int(parts[2])
                    filepath = os.path.join(SERVER_FILES_DIR, filename)
                    conn.sendall(encrypt("OK_TO_SEND".encode('utf-8')))
                    with open(filepath, 'wb') as f:
                        bytes_received = 0
                        while bytes_received < filesize:
                            remaining = filesize - bytes_received
                            chunk_size = min(BUFFER_SIZE, remaining)
                            raw_chunk = conn.recv(chunk_size)
                            if not raw_chunk: break
                            f.write(decrypt(raw_chunk))
                            bytes_received += len(raw_chunk)
                    if bytes_received == filesize:
                        print(f"Received {filename} from '{username}'.")
                        conn.sendall(encrypt(f"OK:Received {filename}".encode('utf-8')))
                    else:
                        print(f"Error receiving {filename} from '{username}'.")
                        if os.path.exists(filepath): os.remove(filepath)

                elif command_str == 'QUIT':
                    print(f"User '{username}' is quitting.")
                    break
        
    except (ConnectionResetError, ConnectionAbortedError):
        print(f"Client '{username}' from {addr} disconnected unexpectedly.")
    except Exception as e:
        print(f"An error occurred with '{username}' from {addr}: {e}")
    finally:
        print(f"Connection with '{username}' from {addr} closed.")

# Main server 
while True:
    try:
        # Wait for a new client connection
        conn, addr = server_socket.accept()

        # Create a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        
        # Start the thread. It will run independently.
        client_thread.start()
    
    except KeyboardInterrupt:
        print("\nServer is shutting down by request (Ctrl+C)...")
        break
    except Exception as e:
        print(f"Error in main server loop: {e}")

server_socket.close()
print("Server shut down complete.")