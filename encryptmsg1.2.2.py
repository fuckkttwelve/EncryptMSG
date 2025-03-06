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

# Function to count messages in a given address
def messagecount(address):
    api_url = f'https://textdb.online/{address}'
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            message_data = json.loads(response.text)
            if isinstance(message_data, dict):
                return message_data.get("msgnum", 0)
            else:
                print(Fore.RED + "Invalid response format.")
                return 0
        elif response.status_code == 404:  # Handle 404 error
            return 0  # Treat non-existent address as having 0 messages
        else:
            print(Fore.RED + f"Failed to retrieve message count: {response.status_code} - {response.text}")
            return 0
    except requests.RequestException as e:
        print(Fore.RED + f"Failed to count messages: {e}")
        return 0

# Function to check SOCKS5 proxy
def check_proxy(proxy, proxyport):
    try:
        socks.set_default_proxy(socks.SOCKS5, proxy, proxyport)
        socket.socket = socks.socksocket
        socket.create_connection(('www.google.com', 80), timeout=15)
        print(Fore.GREEN + 'Proxy is live.')
        return True
    except Exception as e:
        print(Fore.RED + f"Proxy check failed: {e}")
        return False

def useproxy():
    wishtouseproxy = input(Fore.YELLOW + "Make connections with SOCKS5 proxy? (y/n): ").strip().lower()

    if wishtouseproxy == 'y':
        proxy = input(Fore.GREEN + "Enter SOCKS5 proxy: ")
        proxyport = input(Fore.GREEN + "Enter SOCKS5 proxy port: ")
        try:
            proxyport = int(proxyport)
        except ValueError:
            print(Fore.RED + "Invalid port number. Please enter a numeric value.")
            return None, None
        print(Fore.BLUE + "Please allow 15 seconds for connection timeout.")
        if not check_proxy(proxy, proxyport):
            print(Fore.RED + "Proxy is not reachable.")
            return None, None
        return proxy, proxyport
    elif wishtouseproxy == 'n':
        print(Fore.LIGHTRED_EX + "Using standard connection. Not as secure!")
        return None, None
    else:
        print(Fore.RED + "Invalid input. Please enter 'y' or 'n'.")
        return None, None

# Main function to send a message
def send_message():
    proxy, proxyport = useproxy()
    receiving_address = input(Fore.YELLOW + "Enter receiving address: ")
    message = input(Fore.YELLOW + "Enter your message: ")
    decryption_key = generate_key()  # Generate a new key
    print(Fore.YELLOW + f"Generated decryption key: {decryption_key.decode()}")

    encrypted_message = encrypt_message(message, decryption_key)

    # Count the number of messages sent to the address
    msgnum = messagecount(receiving_address) + 1

    # Get previous messages if any
    api_url_read = f'https://textdb.online/{receiving_address}'
    try:
        response_read = requests.get(api_url_read)
        if response_read.status_code == 200:
            existing_data = json.loads(response_read.text)
            existing_messages = existing_data.get("messages", [])
        else:
            existing_messages = []
    except Exception:
        existing_messages = []

    # Prepare data for POST request
    new_messages = existing_messages + [encrypted_message] #appends the new message to the list of old messages.
    api_url = f'https://api.textdb.online/update/?key={quote(receiving_address)}&value={json.dumps({"msgnum": msgnum, "messages": new_messages})}'

    # Send message using textdb.online API
    try:
        proxies = {'http': f'socks5://{proxy}:{proxyport}', 'https': f'socks5://{proxy}:{proxyport}'} if proxy and proxyport else {}
        response = requests.post(api_url, data={'address': receiving_address, 'message': encrypted_message}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, proxies=proxies)

        if response.status_code == 200:
            print(Fore.GREEN + f"Message to {receiving_address} sent successfully.")
        else:
            print(Fore.RED + f"Failed to send message: {response.status_code} - {response.text}")
    except Exception as e:
        print(Fore.RED + f"Failed to send message: {e}")

def delete_address(temp_address):
    api_url = f'https://api.textdb.online/update/?key={temp_address}&value='
    try:
        response = requests.post(api_url)
        if response.status_code == 200:
            print(Fore.GREEN + f"Address {temp_address} deleted successfully.")
            time.sleep(5)
        else:
            print(Fore.RED + f"Failed to delete address: {response.status_code} - {response.text}")
    except Exception as e:
        print(Fore.RED + f"Failed to delete address: {e}")

def read_address(address):
    api_url = f'https://textdb.online/{address}'
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            message_data = json.loads(response.text)
            if isinstance(message_data, dict):
                messages = message_data.get("messages", [])
                msgnum = message_data.get("msgnum", 0)
                print(Fore.GREEN + f"Total messages: {msgnum}")
                for i, enc_msg in enumerate(messages):
                    print(f"{i + 1}: {enc_msg}")
                message_index = int(input(Fore.YELLOW + "Select message number to decrypt: ")) - 1
                if 0 <= message_index < len(messages):
                    key_input = input(Fore.YELLOW + "Enter the decryption key: ").encode()
                    encrypted_message = messages[message_index]
                    try:
                        decrypted_message = decrypt_message(encrypted_message, key_input)
                        print(Fore.GREEN + f"Decrypted message: {decrypted_message}")
                    except Exception as e:
                        print(Fore.RED + f"Failed to decrypt message: {e}")
                else:
                    print(Fore.RED + "Invalid message number.")
            else:
                print(Fore.BLUE + "Received response is not a dictionary. Restart program.")
        else:
            print(Fore.RED + f"Failed to read address: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(Fore.RED + f"Failed to read address: {e}")

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
        print(Fore.GREEN + "Version 1.2.2 - developed by fuckkttwelve")
        print(Fore.RED + "\nMenu:")
        print(Fore.BLUE + "1. Send message")
        print(Fore.BLUE + "2. Read messages from address")
        print(Fore.BLUE + "3. Generate random address")
        print(Fore.BLUE + "4. Delete an address")
        print(Fore.CYAN + "5. Set SOCKS5 proxy")
        print(Fore.RED + "6. Exit")
        choice = input(Fore.YELLOW + "Select an option: ")

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
