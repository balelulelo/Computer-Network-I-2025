if username == "admin":
                    client_socket.send(f"[Server]: Security Question: {security_question}\n".encode())
                    client_socket.send(f"Enter answer: ".encode())
                    entered_passphrase = client_socket.recv(1024).decode().strip()
