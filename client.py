import socket
import os

# Configuration 
HOST = '127.0.0.1'
PORT = 9999
BUFFER_SIZE = 5000

# Encryption
ENCRYPTION_KEY = 0xAF # Same key as server

def encrypt(data):
    """Encrypts byte data using a simple XOR cipher."""
    return bytes([b ^ ENCRYPTION_KEY for b in data])

def decrypt(data):
    """Decrypts byte data using a simple XOR cipher."""
    return bytes([b ^ ENCRYPTION_KEY for b in data])

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f" Connected to secure server at {HOST}:{PORT}")
    
    # Initial server response (expecting AUTH_REQUIRED)
    raw_response = client_socket.recv(1024)
    response = decrypt(raw_response).decode('utf-8')
    
    if response == "AUTH_REQUIRED":
        print("Server requires authentication.")
        username = input("Username: ")
        password = input("Password: ")
        
        # Send authentication details
        auth_string = f"AUTH:{username}:{password}"
        client_socket.sendall(encrypt(auth_string.encode('utf-8')))
        
        # Receive authentication status
        raw_status = client_socket.recv(1024)
        auth_status = decrypt(raw_status).decode('utf-8')
        
        if auth_status == "AUTH_SUCCESS":
            print(" Login successful.")
            
            # Main Menu Loop
            while True:
                print("\n--- Client Menu ---")
                print("1. List files on server")
                print("2. Download a file")
                print("3. Upload a file")
                print("4. Quit")
                choice = input("Enter your choice (1-4): ")

                if choice == '1':
                    client_socket.sendall(encrypt("LIST".encode('utf-8')))
                    raw_data = client_socket.recv(4096)
                    file_list_str = decrypt(raw_data).decode('utf-8')
                    
                    print("\n--- Files Available on Server ---")
                    files = file_list_str.split(',')
                    for f in files:
                        print(f"* {f}")
                    print("---------------------------------")

                elif choice == '2':
                    filename = input("Enter the exact filename to download: ")
                    if not filename:
                        continue
                    
                    client_socket.sendall(encrypt(f"DOWNLOAD:{filename}".encode('utf-8')))
                    raw_response = client_socket.recv(1024)
                    response = decrypt(raw_response).decode('utf-8')
                    
                    if response.startswith("OK:"):
                        filesize = int(response.split(':', 1)[1])
                        print(f"Receiving file '{filename}' ({filesize} bytes)...")
                        
                        with open(filename, 'wb') as f:
                            bytes_received = 0
                            while bytes_received < filesize:
                                remaining = filesize - bytes_received
                                chunk_size = min(BUFFER_SIZE, remaining)
                                
                                raw_chunk = client_socket.recv(chunk_size)
                                if not raw_chunk:
                                    break
                                f.write(decrypt(raw_chunk)) # Decrypt file data
                                bytes_received += len(raw_chunk)
                                
                        if bytes_received == filesize:
                            print(f" Download complete: '{filename}' saved.")
                        else:
                            print("Error: Did not receive the full file.")
                    else:
                        print(f"Server response: {response}")

                elif choice == '3':
                    filepath = input("Enter the path to the local file to upload: ")
                    if not os.path.exists(filepath):
                        print("Error: File not found locally.")
                        continue
                    
                    filesize = os.path.getsize(filepath)
                    filename = os.path.basename(filepath)
                    
                    client_socket.sendall(encrypt(f"UPLOAD:{filename}:{filesize}".encode('utf-8')))
                    
                    raw_response = client_socket.recv(1024)
                    response = decrypt(raw_response).decode('utf-8')
                    
                    if response == "OK_TO_SEND":
                        print(f"Server is ready. Uploading '{filename}'...")
                        with open(filepath, 'rb') as f:
                            while True:
                                chunk = f.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                client_socket.sendall(encrypt(chunk)) # Encrypt file data
                        
                        raw_final_response = client_socket.recv(1024)
                        final_response = decrypt(raw_final_response).decode('utf-8')
                        
                        if final_response.startswith("OK:"):
                            print(f" Upload successful. Server says: {final_response}")
                        else:
                            print(f"Server error after upload: {final_response}")
                    else:
                        print(f"Server response: {response}")

                elif choice == '4':
                    client_socket.sendall(encrypt("QUIT".encode('utf-8')))
                    print("Disconnecting from server.")
                    break

                else:
                    print("Invalid choice. Please enter 1, 2, 3, or 4.")
            
        else:
            print(" Authentication failed. Disconnecting.")

    else:
        print(f"Error: Server sent unexpected response: {response}")

except ConnectionRefusedError:
    print(" Connection refused. Is the server running?")
except (ConnectionResetError, ConnectionAbortedError):
    print(" Server connection lost unexpectedly.")
except Exception as e:
    print(f"An error occurred: {e}")

finally:
    client_socket.close()
    print("Client shut down.")