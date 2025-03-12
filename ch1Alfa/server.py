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

# Read security question from file
security_question = ""
security_answer = ""

try:
    with open(".securityquestion.txt", "r") as file:
        question_line = file.readline().strip()
        security_question, security_answer = question_line.split(":")
except FileNotFoundError:
    print("Error: .securityquestion.txt not found!")
    sys.exit(1)

def xor_encrypt_decrypt(message, key):
    """Encrypt or decrypt a message using XOR."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))

def log_message(username, message):
    """Logs messages into log.txt"""
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    try:
        with open("log.txt", "a") as log_file:
            log_file.write(f"{timestamp} {username}: {message}\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def decrypt_logs():
    """Reads and returns decrypted log messages"""
    try:
        with open("log.txt", "r") as log_file:
            return log_file.readlines()
    except FileNotFoundError:
        return ["[Server]: No log file found.\n"]

def clear_logs():
    """Erases all content inside log.txt"""
    open("log.txt", "w").close()
    return "[Server]: The log has been erased.\n"

def list_users():
    """Displays all usernames stored in users.txt"""
    return "[Server]: Users: " + ", ".join(users.keys()) + "\n"

def is_banned(username):
    return username in banned_users

print("[Server]: Waiting for connections...")

try:
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[Server]: Connection from {client_address}")

        # Step 1: Receive username
        client_socket.send("Enter username: ".encode())
        username = client_socket.recv(1024).decode().strip()

        if is_banned(username):
            client_socket.send("[Server]: You are permanently banned.\n".encode())
            client_socket.close()
            continue

        # Step 2: Receive password
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
                client_socket.send("success!\n".encode())
                print(f"[Server]: User '{username}' logged in successfully.")

                if username == "admin":
                    # Admin needs to answer the security question
                    client_socket.send(f"[Server]: {security_question}\n".encode())
                    client_socket.send("Enter answer: ".encode())

                    entered_passphrase = client_socket.recv(1024).decode().strip()

                    if entered_passphrase == security_answer:
                        client_socket.send("Login successful!.\n".encode())

                        while True:
                            command = client_socket.recv(1024).decode().strip()

                            if command == "shutdown":
                                client_socket.send("[Server]: Shutting down server...\n".encode())
                                print("[Server]: Admin initiated shutdown.")
                                server_socket.close()
                                sys.exit(0)

                            elif command == "decrypt_log":
                                log_data = decrypt_logs()
                                client_socket.send("".join(log_data).encode())

                            elif command == "clear_log":
                                client_socket.send(clear_logs().encode())

                            elif command == "list_users":
                                client_socket.send(list_users().encode())

                            elif command == "exit":
                                client_socket.send("[Server]: Exiting admin mode.\n".encode())
                                break

                            else:
                                client_socket.send("[Server]: Unknown command.\n".encode())

                    else:
                        client_socket.send("[Server]: Incorrect passphrase. Access denied.\n".encode())

                else:
                    encryption_key = username + otp

                    while True:
                        client_socket.send("Enter encrypted message: ".encode())
                        encrypted_message = client_socket.recv(1024).decode().strip()

                        if encrypted_message.lower() == "exit":
                            client_socket.send("[Server]: Goodbye!\n".encode())
                            break

                        decrypted_message = xor_encrypt_decrypt(encrypted_message, encryption_key)
                        log_message(username, decrypted_message)
                        print(f"[{username}]: {decrypted_message}")

                        client_socket.send("[Server]: Message received.\n".encode())

            else:
                failed_attempts[username] = failed_attempts.get(username, 0) + 1
                client_socket.send("[Server]: Incorrect OTP.\n".encode())

        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            client_socket.send("[Server]: Incorrect password.\n".encode())

        client_socket.close()

except KeyboardInterrupt:
    print("\n[Server]: Shutting down...")
    server_socket.close()
    sys.exit(0)
