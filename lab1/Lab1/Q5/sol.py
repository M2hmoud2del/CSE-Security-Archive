import hashlib
import csv
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HASHED_FILE = os.path.join(BASE_DIR, "HashedPWs")
PASSWORD_FILE = os.path.join(BASE_DIR, "LeakedPWs100k")
USERS_FILE = os.path.join(BASE_DIR, "users")
LOGIN_CHECK_FILE = os.path.join(BASE_DIR, "..", ".loginCheck")
OUTPUT_FILE = os.path.join(BASE_DIR, "results.txt")


def verify_login(username, password, login_hashes):
    """Verify credentials using the lab's Login.pyc hashing algorithm."""
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

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = {line.strip() for line in f if line.strip()}

    target_hashes = {}

    with open(HASHED_FILE, "r", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) != 2:
                continue

            username, password_hash = row[0].strip(), row[1].strip().lower()

            if username in users:
                target_hashes.setdefault(password_hash, []).append(username)

    login_hashes = {}

    with open(LOGIN_CHECK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",", 1)
            if len(parts) == 2:
                login_hashes[parts[0]] = parts[1]

    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    found = {}

    for password in passwords:
        for number in range(100):
            candidate = password + f"{number:02d}"
            digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()

            matching_users = target_hashes.get(digest, [])

            for username in matching_users:
                if username not in found and verify_login(
                    username, candidate, login_hashes
                ):
                    found[username] = candidate
                    print(f"Username: {username}")
                    print(f"Password: {candidate}")
                    print("Login verification: SUCCESS")
                    print("-" * 30)

    elapsed = time.perf_counter() - start_time

    print("\n--- Results ---")
    print(f"Users in users file: {len(users)}")
    print(f"Target hash records: {sum(map(len, target_hashes.values()))}")
    print(f"Credentials verified: {len(found)}")
    print(f"Execution time: {elapsed:.4f} seconds")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for username, password in sorted(found.items()):
            f.write(f"{username},{password}\n")

    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()