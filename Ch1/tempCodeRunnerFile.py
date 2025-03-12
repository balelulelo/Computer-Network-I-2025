import socket

server_address = ('localhost', 5000)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)

# Receive and send username
response = client_socket.recv(1024).decode()
print(response, end="")
username = input()
client_socket.send(username.encode())

# Receive and send password
response = client_socket.recv(1024).decode()
print(response, end="")
password = input()
client_socket.send(password.encode())

# Check if authentication passed
response = client_socket.recv(1024).decode()
print(response, end="")

if "OTP" in response:
    otp = input()
    client_socket.send(otp.encode())
    
    # Receive login status
    response = client_socket.recv(1024).decode()
    print(response, end="")

    if "successful" in response:
        while True:
            message = input()
            if not message:
                break
            client_socket.send(message.encode())
            response = client_socket.recv(1024).decode()
            print(response, end="")

client_socket.close()
