
import hashlib
import csv
import os
import sys
import time
import subprocess
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USERS_FILE = os.path.join(BASE_DIR, "users")
PASSWORD_FILE = os.path.join(BASE_DIR, "LeakedPWs100k")
LOGIN_FILE = os.path.join(BASE_DIR, "..", ".loginCheck")
LOGIN_SCRIPT = os.path.join(BASE_DIR, "..", "LoginTemplate.py")
OUTPUT_FILE = os.path.join(BASE_DIR, "results.txt")

EXPOSED_USERS = {"Magdy", "Mostafa"}

CHUNK_SIZE = 25
MAX_WORKERS = min(os.cpu_count() or 2, 8)

TARGET_USERS = []
LOGIN_HASHES = {}
STOP_EVENT = None


def initialize_worker(users, hashes, stop_event):
    global TARGET_USERS, LOGIN_HASHES, STOP_EVENT

    TARGET_USERS = users
    LOGIN_HASHES = hashes
    STOP_EVENT = stop_event


def calculate_hash(username, password):
    h = hashlib.sha256()
    h.update((username + password).encode("utf-8"))

    for _ in range(90000):
        h.update(h.digest())

    return h.hexdigest()


def search_chunk(task):
    start_index, passwords = task

    for i, password in enumerate(passwords):

        if i % 5 == 0 and STOP_EVENT.is_set():
            return None

        for username in TARGET_USERS:

            hashed = calculate_hash(username, password)

            if hashed == LOGIN_HASHES[username]:
                STOP_EVENT.set()
                return start_index + i, username, password

    return None


def main():
    start_time = time.perf_counter()

    with open(USERS_FILE, "r", encoding="utf-8") as file:
        users = [line.strip() for line in file if line.strip()]

    login_hashes = {}

    with open(LOGIN_FILE, "r", encoding="utf-8") as file:
        for row in csv.reader(file):
            if len(row) == 2:
                username = row[0].strip()
                password_hash = row[1].strip()
                login_hashes[username] = password_hash

    targets = [
        user for user in users
        if user not in EXPOSED_USERS and user in login_hashes
    ]

    with open(PASSWORD_FILE, "r", encoding="utf-8") as file:
        passwords = [line.strip() for line in file if line.strip()]

    if not targets:
        print("No target users found.")
        return

    if not passwords:
        print("Password dictionary is empty.")
        return

    chunks = [
        (i, passwords[i:i + CHUNK_SIZE])
        for i in range(0, len(passwords), CHUNK_SIZE)
    ]

    workers = min(MAX_WORKERS, len(chunks))

    print("Target users:", len(targets))
    print("Dictionary entries:", len(passwords))
    print("Processes:", workers)
    print("\nStarting dictionary attack...\n")

    found = None
    completed = 0

    with multiprocessing.Manager() as manager:

        stop_event = manager.Event()

        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=initialize_worker,
            initargs=(targets, login_hashes, stop_event)
        ) as executor:

            futures = [
                executor.submit(search_chunk, chunk)
                for chunk in chunks
            ]

            for future in as_completed(futures):

                try:
                    result = future.result()

                except Exception as error:
                    print("Worker error:", error)
                    continue

                completed += 1

                if result is not None:
                    found = result

                    index, username, password = result

                    print("\n[+] MATCH FOUND!")
                    print("Username:", username)
                    print("Password:", password)
                    print("Dictionary position:", index + 1)

                    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
                        file.write(f"{username},{password}\n")

                    print("Saved to:", OUTPUT_FILE)

                    stop_event.set()

                    for pending in futures:
                        if pending != future:
                            pending.cancel()

                    break

                if completed % 20 == 0:
                    elapsed = time.perf_counter() - start_time
                    print(
                        f"Completed chunks: {completed}/{len(chunks)}"
                        f" | Time: {elapsed:.2f}s"
                    )

    if found is not None:

        _, username, password = found

        if os.path.isfile(LOGIN_SCRIPT):

            try:
                result = subprocess.run(
                    [sys.executable, LOGIN_SCRIPT, username, password],
                    cwd=BASE_DIR,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                print("\n--- Login Verification ---")
                print(result.stdout.strip() or result.stderr.strip())

            except (OSError, subprocess.TimeoutExpired) as error:
                print("Login verification error:", error)

        else:
            print("LoginTemplate.py not found.")

    else:
        print("\nNo matching credentials found.")

    elapsed = time.perf_counter() - start_time
    print(f"\nExecution Time: {elapsed:.4f} seconds")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
