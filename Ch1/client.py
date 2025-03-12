import socket

server_address = ('localhost', 5000)

def xor_encrypt_decrypt(message, key):
    # """Encrypt or decrypt a message using XOR."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)

# Receive initial server prompt
response = client_socket.recv(1024).decode()
print(response, end=" ")

# Send username
username = input()
client_socket.send(username.encode())

# Receive password prompt
response = client_socket.recv(1024).decode()
print(response, end=" ")

# Send password
password = input()
client_socket.send(password.encode())

# Receive authentication response
response = client_socket.recv(1024).decode()
print(response)

if "OTP" in response:
    # Receive OTP from server
    otp_response = client_socket.recv(1024).decode()
    print(otp_response, end=" ")

    otp = input()
    client_socket.send(otp.encode())

    # Receive login success or failure message
    response = client_socket.recv(1024).decode()
    print(response)

    if "successful" in response:
        encryption_key = username + otp  # Use username + OTP as encryption key

        while True:
            message = input("Enter message (type 'exit' to quit): ")
            encrypted_message = xor_encrypt_decrypt(message, encryption_key)

            client_socket.send(encrypted_message.encode())

            if message.lower() == "exit":
                break

            # Receive server acknowledgment
            response = client_socket.recv(1024).decode()
            print(response)

client_socket.close()
