import hashlib
import itertools
import time
from concurrent.futures import ThreadPoolExecutor
import random

def attack_mode():
    return int(input("(1) Brute Force attack  | (2) Dictionary attack | (3) Dictionary attack with salt  | (4) Number attack\nEnter the type of attack: "))

def print_cracked(cracked_list, method):
    if cracked_list:
        print(f"Cracked passwords using {method}:")
        for x, y in cracked_list:
            print(f"Hash: {x}, Password: {y}")
    else:
        print(f"Can't crack with {method}")

def number_attack(maxvalue, hash_values):
    for hash_value_with_salt in hash_values:
        hash_only, salt = hash_value_with_salt.split(":")
        for i in range(1, maxvalue + 1):
            calculated_hash = hashlib.sha512((str('0') + str(i) + salt).encode('utf-8')).hexdigest()
            if calculated_hash == hash_only:
                print(f"Password found: {hash_only} : {i}")
                break

def brute_force_subset(start, end, hashes):
    cracked = []
    for n in range(start, end + 1):                                 # Iterate over the length of passwords
        for c in itertools.product(chars, repeat=n):                # Generate potential passwords of length n
            if len(hashes) == 0:                                    # If all hashes are cracked, exit early
                return cracked
            password = ''.join(c)                                      #Convert tuple to string
            hashed_password = hashlib.sha512(password.encode()).hexdigest()  # Hash the potential password
            if hashed_password in hashes:                                    # Check if the hashed potential password is in our list of hashes to crack
                cracked.append((hashed_password, password))
                hashes.remove(hashed_password)                               # Remove the cracked hash
    return cracked

def execute_brute_force_threads(modes, hashes):                      #Distributes the task of brute-forcing password hashes among multiple threads.
    n = 8                                                            # Maximum length of password to try
    thread_count = 5                                                 # Number of threads to use for concurrent processing
    passwords_per_thread = n // thread_count                         # Distribute the range of password lengths across the threads
    with ThreadPoolExecutor(max_workers=thread_count) as executor:   # Create a ThreadPoolExecutor to manage our threads
        # Start threads and submit the brute_force_subset tasks
        threads = [executor.submit(brute_force_subset, i * passwords_per_thread + 1, (i + 1) * passwords_per_thread, modes, hashes) for i in range(thread_count)]
        for thread in threads:                                       # Collect results from threads as they complete
            found_passwords.extend(thread.result())                  # Extend the global variable with the results

def replace_rule(password):
    substitutions = {'o': '0', 'e': '3', 'a': '@', 's': '$', 't': '7'}
    passwords = {password, password.capitalize()}
    for original, substitute in substitutions.items():
        for var in list(passwords):  # Using list to iterate over a snapshot of the set
            new_variation = var.replace(original, substitute)
            passwords.add(new_variation)
    return list(passwords)

def delete_rule(password):
    password = password.capitalize()
    return ''.join([char for char in password if char.isalpha()])    # This will remove numbers and symbols, keeping only alphabetic characters

def append_rule(password):
    if not password:  # Handle empty strings
        return [password]
    special = "_!£$%^&*()@#+-"
    numbers = "1234567890"
    passwords = [password]  # Start with the original word
    capitalized_password = password[0].upper() + password[1:].lower()  # Add the capitalized version
    passwords.append(capitalized_password)
    for n in range(1, 3):    # Don't set the max value of this to be greater than 5 or your system may crash. 4 is ideal.
        for p in itertools.product(special, repeat=n):
            passwords.append(capitalized_password + ''.join(p))
            passwords.append(password_chain + ''.join(p))
        for p in itertools.product(numbers, repeat=n):
            passwords.append(capitalized_password + ''.join(p))
            passwords.append(password_chain + ''.join(p))
    return passwords

def add_number(password):
    common = ['321', '1234','01234', '1234567890', '132', '0123', '12345']
    return [password.capitalize() + str(i) for i in list(range(120, 125)) + list(range(2013, 2024)) + common + [x[::-1] for x in common]]
def append_symbols(password):
    common = ["!@#", "!@#$", "!@#$", "!@#£", "!@£$%", "!@$%^", "!@$%^&", "!@$%^&*", "%", "$", "£", "?", "#!@", "#@!£$%", "#@!"]
    return [password.capitalize() + i for i in common]

def mangle_and_append(password):
    altered_pass = {password, password.capitalize()}
    c1 = ["!@#$", "!", "!@", "!@#£$", "!@#$%^&*", "?!@", "?!",
          "!@#£$%^",  "!@#$%", "!@#", "!@#£$%^&*", "@#$%",  "#$%^", "!@#$%^&*",
          "%", "$", "£", "?", "!@$%^", "#", "#!@", "#@!£$%", "#@!", "!@#$%^&", "!@#$%^", "!@$%", "!@#£$"]
    numbered_passwords = add_number(password)
    for num in numbered_passwords:
        altered_pass.update({num + sequence for sequence in c1})
    # Add permutations of special_chars
    #altered_pass.update({word + ''.join(p) for n in range(1, 1) for p in itertools.product(special_chars, repeat=n) for word in altered_pass})
    return list(altered_pass)

def apply_combined_rules(password):
    modified_passwords = replace_rule(password)  # First, apply the replace_rule
    mangled_passwords = []
    for pwd in modified_passwords:
        mangled_passwords.extend(mangle_and_append(pwd))
    return mangled_passwords  # Next, apply the mangle rule to the modified password

def apply_transformation_rule(password, rule_choice):
    rules = {0: lambda p: [p], 1: mangle_and_append, 2: replace_rule, 3: delete_rule, 4: apply_combined_rules, 5: append_rule, 6: add_number, 7: append_symbols}
    return rules.get(rule_choice, lambda _: [])(password)

def dictionary_attack(hashes):
    cracked = []
    cracked_hashes = set()
    processed_words = 0
    file_choice = int(input("(1) Use Crack-station (15GB)  | (2) Use rockyou (130MB)  | (3) Use PwnedpasswordsTop100k (5MB)  | (4) Use 10-million-list-top-1000000 (8MB)\nEnter your dictionary choice: "))
    file_path = dictionaries.get(file_choice, "")
    try:
        with open(file_path, 'r', errors="ignore") as file:
            rule_choice = int(input("(0) No rules | (1) Use Mangle and append | (2) Use replace_rule | (3) Use delete_rule | (4) Combine Rules  |  (5) Append Rule | (6) Add number\nEnter your rule choice: "))
            for line in file:
                password = line.strip()
                #Important for noise reduction, especially long digits already tested.
                if not password[0].isalpha(): 	
                    continue
                if len(password) == 0:     #In case we reach an empty line
                    continue
                passwords_to_check = apply_transformation_rule(password, rule_choice)
                for p in passwords_to_check:
                    hash_pass = hashlib.sha512(p.encode('utf-8')).hexdigest()   #Encode into a hexadecimal using a hash function supplied by hashlib
                    if hash_pass.strip() in hashes and hash_pass.strip() not in cracked_hashes:
                        cracked.append((hash_pass, p))
                        cracked_hashes.add(hash_pass)
                        print("Password cracked:", hash_pass, ":", p)   #Output if our wordlist line hashed is equal to one of the hashes in our dictionary
                processed_words += 1     #keep track of the passwords checked and display this to the user (helps to know it is working)
                if processed_words % 20000 == 0:
                    print(f"We have checked: {processed_words} passwords and cracked : {len(cracked)} passwords")
        return cracked
    except FileNotFoundError:
        print("File not found.")
        return []
def dictionary_attack_with_salt(hashes):
    cracked = []
    processed_words = 0
    file_choice = int(input("(1) Use Crack-station (15GB)  | (2) Use rockyou (130MB)  | (3) Use PwnedpasswordsTop100k (5MB)  | (4) Use 10-million-list-top-1000000 (8MB)\nEnter your dictionary choice: "))
    file_path = dictionaries.get(file_choice, "")
    hash_set = set(hashes)
    try:
        with open(file_path, 'r', errors="ignore") as file:
            rule_choice = int(input("(0) No rules | (1) Use Mangle and append | (2) Use replace_rule | (3) Use delete_rule | (4) Combine Rules  |  (5) Append Rule  |  (6) Add number  |  (7) Add symbols\nEnter your rule choice: "))
            for line in file:
                dictionary_password = line.strip()
                if not dictionary_password:
                    continue
                if not dictionary_password[0].isalpha():
                    continue
                passwords_to_check = apply_transformation_rule(dictionary_password, rule_choice)   #From our selection of rules we select the passwords to check
                for p in passwords_to_check:
                    for hash_pass in list(hash_set):  # using list(hash_set) to avoid "Set changed size during iteration" error
                        hash_only, salt = hash_pass.split(":")
                        hash_attempt = hashlib.sha512((p + salt).encode('utf-8')).hexdigest()
                        if hash_attempt == hash_only:
                            cracked.append((hash_attempt, p))
                            hash_set.remove(hash_pass)
                            print(f"Password cracked for salt {salt}: {p}")
                processed_words += 1
                if processed_words % 2000 == 0:
                    print(f"We have checked: {processed_words} passwords and cracked : {len(cracked)} passwords")
        return cracked
    except FileNotFoundError:
        print("File not found.")
        return []
def main():
    found_passwords.clear()
    mode = attack_mode()   #Call our function attack_mode
    first_task_list = {}
    second_task_list = {}
    third_task_list = {
        '63328352350c9bd9611497d97fef965bda1d94ca15cc47d5053e164f4066f546828eee451cb5edd6f2bba1ea0a82278d0aa76c7003c79082d3a31b8c9bc1f58b:dbc3ab99',
        '86ed9024514f1e475378f395556d4d1c2bdb681617157e1d4c7d18fb1b992d0921684263d03dc4506783649ea49bc3c9c7acf020939f1b0daf44adbea6072be6:fa46510a',
        '16ac21a470fb5164b69fc9e4c5482e447f04f67227102107ff778ed76577b560f62a586a159ce826780e7749eadd083876b89de3506a95f51521774fff91497e:9e8dc114',}

    if mode == 1:
        start_time = time.time()
        execute_brute_force_threads(mode, first_task_list)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Brute force attack completed in {elapsed_time:.2f} seconds.")
        print_cracked(found_passwords, "brute-force")
    elif mode == 2:
        start_time = time.time()
        cracked = dictionary_attack(second_task_list)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Dictionary attack completed in {elapsed_time:.2f} seconds.")
        print_cracked(cracked, "dictionary attack")
        cracked.clear()
    elif mode == 3:
        start_time = time.time()
        cracked_passwords = dictionary_attack_with_salt(third_task_list)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Dictionary attack with salt completed in {elapsed_time:.2f} seconds.")
        print_cracked(cracked_passwords, "Dictionary Attack with Salt")
    elif mode == 4:
        start_time = time.time()
        number_attack(900000000, third_task_list)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Number attack completed in {elapsed_time:.2f} seconds.")


#chars = "abcdefghijklmnopqrstuvwxyz0123456789"
found_passwords = []    #Global password list: check clear conditions on modes

dictionaries = {
    1: "D:\\1.txt",
    # this is realuniq.lst or better known as crack-station. Don't use unless low computational rule (https://github.com/yuqian5/PasswordCollection)
    2: "D:\\rockyou.txt",  # Again not really used but well known. Did not crack anything that 3 and 4 did not.
    3: "D:\\PwnedPasswordsTop100k.txt",
    # Please note that this file contains the top 100,000 passwords from the Have I Been Pwned (https://haveibeenpwned.com) concatenated with english dictionary and common keystroke passwords(https://github.com/yuqian5/PasswordCollection) and hashcat samples based on previously cracked passwords
    4: "D:\\10-million-password-list-top-1000000.txt"}

if __name__ == "__main__":
    main()

