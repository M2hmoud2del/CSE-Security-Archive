import hashlib
import csv
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PWNED_FILE = os.path.join(BASE_DIR, "PwnedPWfile")
USERS_FILE = os.path.join(BASE_DIR, "users")
LOGIN_FILE = os.path.join(BASE_DIR, "..", ".loginCheck")
OUTPUT_FILE = os.path.join(BASE_DIR, "results.txt")


def verify_login(username, password, login_hashes):
    stored_hash = login_hashes.get(username)

    if stored_hash is None:
        return False

    h = hashlib.sha256()
    h.update((username + password).encode("utf-8"))

    for _ in range(90000):
        h.update(h.digest())

    return h.hexdigest() == stored_hash


def main():
    start_time = time.perf_counter()

    # Read target users
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = [line.strip() for line in f if line.strip()]

    # Read login hashes
    login_hashes = {}

    with open(LOGIN_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",", 1)

            if len(parts) == 2:
                login_hashes[parts[0]] = parts[1]

    # Read exposed username/password pairs
    leaked_entries = []

    with open(PWNED_FILE, "r", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                leaked_user = row[0].strip()
                password = row[1].strip()

                if password:
                    leaked_entries.append((leaked_user, password))

    found = None
    attempts = set()

    # Phase 1: Try passwords associated with matching usernames first.
    users_by_lower = {user.lower(): user for user in users}

    for leaked_user, password in leaked_entries:
        username = users_by_lower.get(leaked_user.lower())

        if username is None:
            continue

        attempts.add((username, password))

        if verify_login(username, password, login_hashes):
            found = (username, password)
            break

    # Phase 2: If needed, test all leaked passwords against target users.
    if found is None:
        passwords = list(dict.fromkeys(
            password for _, password in leaked_entries
        ))

        for password in passwords:
            for username in users:
                if (username, password) in attempts:
                    continue

                if verify_login(username, password, login_hashes):
                    found = (username, password)
                    break

            if found is not None:
                break

    elapsed = time.perf_counter() - start_time

    print("\n--- Q4 Results ---")

    if found:
        username, password = found

        print(f"Username: {username}")
        print(f"Password: {password}")
        print("Verification: SUCCESS")

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"{username},{password}\n")

        print(f"Results saved to: {OUTPUT_FILE}")
    else:
        print("No matching credentials found.")

    print(f"Execution Time: {elapsed:.4f} seconds")


if __name__ == "__main__":
    main()