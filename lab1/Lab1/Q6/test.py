import hashlib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SALTED_FILE = os.path.join(BASE_DIR, "SaltedPWs")


def login():
    username = input("Username: ").strip()
    password = input("Password: ")

    with open(SALTED_FILE, "r", encoding="utf-8") as file:
        for line in file:
            parts = line.strip().split(",")

            if len(parts) != 3:
                continue

            user, salt, stored_hash = parts

            if user == username:
                calculated_hash = hashlib.sha256(
                    (salt + password).encode("utf-8")
                ).hexdigest()

                if calculated_hash == stored_hash:
                    print("Login successful!")
                else:
                    print("Login failed: incorrect password.")
                return

    print("User not found.")


if __name__ == "__main__":
    login()