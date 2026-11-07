
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
    if username not in login_hashes:
        return False

    h = hashlib.sha256()
    h.update((username + password).encode("utf-8"))

    for _ in range(90000):
        h.update(h.digest())

    return h.hexdigest() == login_hashes[username]


def main():
    start_time = time.perf_counter()

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = [line.strip() for line in f if line.strip()]

    login_hashes = {}

    with open(LOGIN_FILE, "r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 2:
                login_hashes[row[0].strip()] = row[1].strip()

    leaked_entries = []

    with open(PWNED_FILE, "r", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                username = row[0].strip()
                password = row[1].strip()

                if password:
                    leaked_entries.append((username, password))

    found = None
    attempts = set()

    users_by_lower = {
        user.lower(): user for user in users
    }

    # First, check passwords against their leaked usernames.
    for leaked_user, password in leaked_entries:

        username = users_by_lower.get(leaked_user.lower())

        if username is None:
            continue

        attempts.add((username, password))

        if verify_login(username, password, login_hashes):
            found = (username, password)
            break

    # If no match was found, check the leaked passwords against all users.
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

    if found is not None:

        username, password = found

        print("Username:", username)
        print("Password:", password)
        print("Verification: SUCCESS")

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"{username},{password}\n")

        print("Results saved to:", OUTPUT_FILE)

    else:
        print("No matching credentials found.")

    print(f"Execution Time: {elapsed:.4f} seconds")


if __name__ == "__main__":
    main()
