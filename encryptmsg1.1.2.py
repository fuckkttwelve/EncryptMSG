import random
import string
import socks
import socket
import json
import time
import requests
from cryptography.fernet import Fernet
import colorama
from colorama import Fore, init
from requests.utils import quote

# Initialize colorama
init()

# Function to generate a random temporary address
def generate_temp_address():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=35))

# Function to generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Function to encrypt a message
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

# Function to decrypt a message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

# Function to check SOCKS5 proxy
def check_proxy(proxy, proxyport):
    try:
        socks.set_default_proxy(socks.SOCKS5, proxy, proxyport)
        socket.socket = socks.socksocket
        # Try to connect to a known host
        socket.create_connection(('www.google.com', 80), timeout=15)
        print('Proxy is live.')
        return True
    except Exception as e:
        print(f"Proxy check failed: {e}")
        return False

def useproxy():
    wishtouseproxy = input("Make connections with SOCKS5 proxy? (y/n): ").strip().lower()

    if wishtouseproxy == 'y':
        proxy = input("Enter SOCKS5 proxy: ")
        proxyport = input("Enter SOCKS5 proxy port: ")
        try:
            proxyport = int(proxyport)
        except ValueError:
            print("Invalid port number. Please enter a numeric value.")
            return None, None
        print("Please allow 15 seconds for connection timeout.")
        if not check_proxy(proxy, proxyport):
            print("Proxy is not reachable.")
            return None, None
        return proxy, proxyport
    elif wishtouseproxy == 'n':
        print("Using standard connection. Not as secure!")
        return None, None
    else:
        print("Invalid input. Please enter 'y' or 'n'.")
        return None, None

# Main function to send a message
def send_message():
    decryption_key = generate_key()  # Generate a new key
    print(f"Generated decryption key: {decryption_key.decode()}")

    proxy, proxyport = useproxy()
    receiving_address = input("Enter receiving address: ")
    message = input("Enter your message: ")

    encrypted_message = encrypt_message(message, decryption_key)
    print(f"Sending message to {receiving_address}: {encrypted_message}")

    # Prepare data for POST request
    api_url = f'https://api.textdb.online/update/?key={quote(receiving_address)}&value={json.dumps({"addresssent": generate_temp_address(), "message": encrypted_message})}'

    # Send message using textdb.online API
    try:
        proxies = {'http': f'socks5://{proxy}:{proxyport}', 'https': f'socks5://{proxy}:{proxyport}'} if proxy and proxyport else {}
        response = requests.post(api_url, data={'address': receiving_address, 'message': encrypted_message}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, proxies=proxies)

        if response.status_code == 200:
            print(f"Message to {receiving_address} sent successfully.")
        else:
            print(f"Failed to send message: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Failed to send message: {e}")

def delete_address(temp_address):
    api_url = f'https://api.textdb.online/update/?key={temp_address}&value='
    try:
        response = requests.post(api_url)
        if response.status_code == 200:
            print(f"Address {temp_address} deleted successfully.")
        else:
            print(f"Failed to delete address: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Failed to delete address: {e}")

def read_address(address):
    api_url = f'https://textdb.online/{address}'
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            message = json.loads(response.text)
            if isinstance(message, dict):  # Expecting a dictionary
                key_input = input("Enter the decryption key: ").encode()
                addresssent = message.get("addresssent")
                encrypted_message = message.get("message")
                if addresssent and encrypted_message:  # Check if both address sent and message exist
                    try:
                        decrypted_message = decrypt_message(encrypted_message, key_input)
                        print(f"Decrypted message: {decrypted_message}")
                    except Exception as e:
                        print(f"Failed to decrypt message: {e}")
                else:
                    print("Invalid message format: missing addresssent or message")
            else:
                print("Received response is not a dictionary. Response: ", message)
        else:
            print(f"Failed to read address: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"Failed to read address: {e}")

def main_menu():
    while True:
        print(Fore.RED + """+---------------------------------------------------------------------------+
|                                                                           |
|  ▄████▄   ██▀███  ▓██   ██▓ ██▓███  ▄▄▄█████▓ ███▄ ▄███▓  ██████   ▄████  |
| ▒██▀ ▀█  ▓██ ▒ ██▒ ▒██  ██▒▓██░  ██▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒▒██    ▒  ██▒ ▀█▒ |
| ▒▓█    ▄ ▓██ ░▄█ ▒  ▒██ ██░▓██░ ██▓▒▒ ▓██░ ▒░▓██    ▓██░░ ▓██▄   ▒██░▄▄▄░ |
| ▒▓▓▄ ▄██▒▒██▀▀█▄    ░ ▐██▓░▒██▄█▓▒ ▒░ ▓██▓ ░ ▒██    ▒██   ▒   ██▒░▓█  ██▓ |
| ▒ ▓███▀ ░░██▓ ▒██▒  ░ ██▒▓░▒██▒ ░  ░  ▒██▒ ░ ▒██▒   ░██▒▒██████▒▒░▒▓███▀▒ |
| ░ ░▒ ▒  ░░ ▒▓ ░▒▓░   ██▒▒▒ ▒▓▒░ ░  ░  ▒ ░░   ░ ▒░   ░  ░▒ ▒▓▒ ▒ ░ ░▒   ▒  |
|   ░  ▒     ░▒ ░ ▒░ ▓██ ░▒░ ░▒ ░         ░    ░  ░      ░░ ░▒  ░ ░  ░   ░  |
| ░          ░░   ░  ▒ ▒ ░░  ░░         ░      ░      ░   ░  ░  ░  ░ ░   ░  |
| ░ ░         ░      ░ ░                              ░         ░        ░  |
| ░                  ░ ░                                                    |
|                                                                           |
+---------------------------------------------------------------------------+""")
        print(Fore.GREEN + "Version 1.1.2 - developed by fuckkttwelve")
        print(Fore.RED + "\nMenu:")
        print(Fore.BLUE + "1. Send a message")
        print(Fore.BLUE + "2. Read a message from an address")
        print(Fore.BLUE + "3. Generate random address")
        print(Fore.BLUE + "4. Delete an address")
        print(Fore.CYAN + "5. Set SOCKS5 proxy")
        print(Fore.RED + "6. Exit")
        choice = input(Fore.RED + "Select an option: ")

        if choice == '1':
            send_message()
        elif choice == '2':
            address = input("Enter the address to read: ")
            read_address(address)
        elif choice == '3':
            temp_address = generate_temp_address()
            print(f"Generated temporary address: {temp_address}")
            time.sleep(5)
        elif choice == '4':
            address = input("Enter the address to delete: ")
            delete_address(address)
        elif choice == '5':
            useproxy()
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == '__main__':
    main_menu()
