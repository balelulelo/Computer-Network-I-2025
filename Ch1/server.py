import socket
import sys
import random
import time
import os

# Server configuration
server_address = ('localhost', 5000)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(server_address)
server_socket.listen(5)

# Load users from file
users = {}
failed_attempts = {}
banned_users = set()

try:
    with open("users.txt", "r") as file:
        for line in file:
            username, password = line.strip().split(":")
            users[username] = password
except FileNotFoundError:
    print("Error: users.txt not found!")
    sys.exit(1)

def xor_encrypt_decrypt(message, key):
    # """Encrypt or decrypt a message using XOR."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))

def log_message(username, message, log_key):
    # """Logs the encrypted message with timestamp into log.txt"""
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")

    try:
        with open("lognigga.txt", "a") as log_file:
            log_file.write(f"{timestamp} {username}: {message}\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def is_banned(username):
    return username in banned_users

print("[Server]: Waiting for connections...")

try:
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[Server]: Connection from {client_address}")

        # Receive username
        client_socket.send("Enter username: ".encode())
        username = client_socket.recv(1024).decode().strip()

        if is_banned(username):
            client_socket.send("[Server]: You are permanently banned.\n".encode())
            client_socket.close()
            continue

        # Receive password
        client_socket.send("Enter password: ".encode())
        password = client_socket.recv(1024).decode().strip()

        if username in users and users[username] == password:
            client_socket.send("[Server]: Password correct. Generating OTP...\n".encode())
            failed_attempts[username] = 0  

            otp = str(random.randint(1000, 9999))
            client_socket.send(f"[Server]: Your OTP is {otp}\n".encode())

            client_socket.send("Enter OTP: ".encode())
            entered_otp = client_socket.recv(1024).decode().strip()

            if entered_otp == otp:
                client_socket.send("Login successful! You can now send encrypted messages.\n".encode())
                print(f"[Server]: User '{username}' logged in successfully.")

                encryption_key = username + otp  # Key for message encryption
                log_key = username + users[username]  # Key for log encryption

                while True:
                    client_socket.send("Enter encrypted message: ".encode())
                    encrypted_message = client_socket.recv(1024).decode().strip()
                    if encrypted_message.lower() == "exit":
                        client_socket.send("[Server]: Goodbye!\n".encode())
                        break

                    # Decrypt for server console
                    decrypted_message = xor_encrypt_decrypt(encrypted_message, encryption_key)


                    # Logging the encrypted message
                    log_message(username, encrypted_message, log_key)
                    print(f"[{username} (decrypted)]: {decrypted_message}")

                    client_socket.send("[Server]: Message received.\n".encode())

            else:
                failed_attempts[username] = failed_attempts.get(username, 0) + 1
                client_socket.send("[Server]: Incorrect OTP.\n".encode())
                if failed_attempts[username] >= 2:
                    banned_users.add(username)
                    client_socket.send("[Server]: You are permanently banned.\n".encode())

        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            client_socket.send("[Server]: Incorrect password.\n".encode())
            if failed_attempts[username] >= 2:
                banned_users.add(username)
                client_socket.send("[Server]: You are permanently banned.\n".encode())

        client_socket.close()

except KeyboardInterrupt:
    print("\n[Server]: Shutting down...")
    server_socket.close()
    sys.exit(0)
