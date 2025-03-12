import socket

server_address = ('localhost', 5000)

def xor_encrypt_decrypt(message, key):
    """Encrypt or decrypt a message using XOR."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)

def receive_message():
    """Receives and prints server messages"""
    return client_socket.recv(1024).decode()

def send_message(message):
    """Sends messages to the server"""
    client_socket.send(message.encode())

# Step 1: Username
print(receive_message(), end=" ")  
username = input()
send_message(username)

# Step 2: Password
print(receive_message(), end=" ")
password = input()
send_message(password)

# Step 3: Authentication Response
response = receive_message()
print(response)

if "OTP" in response:
    print(receive_message(), end=" ")
    otp = input()
    send_message(otp)

    response = receive_message()
    print(response)

    if "success" in response:
        encryption_key = username + otp

        if username == "admin":
            # Step 4: Receive security question
            security_question = receive_message()  
            print(security_question)  

            prompt = receive_message()  
            print(prompt, end=" ")  

            passphrase = input()
            send_message(passphrase)

            response = receive_message()
            print(response)

            if "successful" in response:
                while True:
                    command = input("\nEnter command: ")
                    send_message(command)

                    if command.lower() == "exit":
                        break

                    print(receive_message())

        else:
            while True:
                message = input("Enter message (type 'exit' to quit): ")
                encrypted_message = xor_encrypt_decrypt(message, encryption_key)
                send_message(encrypted_message)

                if message.lower() == "exit":
                    break

                print(receive_message())

client_socket.close()
