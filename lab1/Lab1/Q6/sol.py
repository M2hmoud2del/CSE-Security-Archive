
import hashlib
import os
import time
from multiprocessing import Pool, cpu_count

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SALTED_FILE = os.path.join(BASE_DIR, "SaltedPWs")
PASSWORD_FILE = os.path.join(BASE_DIR, "LeakedPWs100k")
USERS_FILE = os.path.join(BASE_DIR, "users")

def crack_user(args):
    username, salt, target_hash, passwords = args

    for password in passwords:
        for digit in "0123456789":
            candidate = password + digit
            guess = hashlib.sha256(
                (salt + candidate).encode("utf-8")
            ).hexdigest()

            if guess == target_hash:
                return username, candidate

    return None


def main():
    start_time = time.perf_counter()

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        known_users = {line.strip() for line in f if line.strip()}

    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    targets = []

    with open(SALTED_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")

            if len(parts) != 3:
                continue

            username, salt, target_hash = parts

            if username not in known_users:
                targets.append(
                    (username, salt, target_hash, passwords)
                )

    print(f"Users to check: {len(targets)}")
    print(f"Passwords in dictionary: {len(passwords)}")

    with Pool(processes=cpu_count()) as pool:
        for result in pool.imap_unordered(
            crack_user, targets, chunksize=1
        ):
            if result is not None:
                username, password = result

                print("\nPassword found!")
                print(f"Username: {username}")
                print(f"Password: {password}")

                pool.terminate()
                break
        else:
            print("\nNo matching password found.")

    elapsed = time.perf_counter() - start_time
    print(f"\nExecution Time: {elapsed:.4f} seconds")


if __name__ == "__main__":
    main()
