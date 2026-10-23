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
LOGIN_SCRIPT = os.path.abspath(
    os.path.join(BASE_DIR, "..", "LoginTemplate.py")
)
OUTPUT_FILE = os.path.join(BASE_DIR, "results.txt")

# Users already discovered in previous questions.
EXPOSED_USERS = {"Magdy", "Mostafa"}

CHUNK_SIZE = 25
MAX_WORKERS = min(os.cpu_count() or 2, 8)

# Worker processes share these values through the initializer.
TARGET_USERS = []
LOGIN_HASHES = {}
STOP_EVENT = None


def initialize_worker(users, hashes, stop_event):
    global TARGET_USERS, LOGIN_HASHES, STOP_EVENT

    TARGET_USERS = users
    LOGIN_HASHES = hashes
    STOP_EVENT = stop_event


def calculate_hash(username, password):
    """
    Reproduce the hashing algorithm in LoginTemplate.py exactly.
    """
    h = hashlib.sha256()
    h.update((username + password).encode("utf-8"))

    for _ in range(90000):
        h.update(h.digest())

    return h.hexdigest()


def search_chunk(task):
    """
    Search a chunk of dictionary entries against the target accounts.
    """
    start_index, passwords = task

    for offset, password in enumerate(passwords):

        # Check periodically to let workers stop when a match is found.
        if offset % 5 == 0 and STOP_EVENT.is_set():
            return None

        for username in TARGET_USERS:
            calculated_hash = calculate_hash(username, password)

            if calculated_hash == LOGIN_HASHES[username]:
                STOP_EVENT.set()
                return start_index + offset, username, password

    return None


def main():
    start_time = time.perf_counter()

    # Load the target usernames.
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = [line.strip() for line in f if line.strip()]

    # Load the stored password hashes used by the login script.
    login_hashes = {}

    with open(LOGIN_FILE, "r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 2:
                login_hashes[row[0].strip()] = row[1].strip()

    # Exclude users already identified in previous questions.
    targets = [
        username
        for username in users
        if username not in EXPOSED_USERS
        and username in login_hashes
    ]

    # Load the leaked password dictionary.
    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not targets:
        print("No target users found. Check Q3/users and .loginCheck.")
        return

    if not passwords:
        print("The password dictionary is empty.")
        return

    chunks = [
        (start, passwords[start:start + CHUNK_SIZE])
        for start in range(0, len(passwords), CHUNK_SIZE)
    ]

    workers = min(MAX_WORKERS, len(chunks))

    print(f"Target users: {len(targets)}", flush=True)
    print(f"Dictionary entries: {len(passwords)}", flush=True)
    print(f"Processes: {workers}", flush=True)
    print("Starting multiprocessing dictionary attack...\n", flush=True)

    found = None
    completed_chunks = 0

    # Manager.Event works across processes on Windows and other platforms.
    with multiprocessing.Manager() as manager:
        stop_event = manager.Event()

        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=initialize_worker,
            initargs=(targets, login_hashes, stop_event),
        ) as executor:

            futures = {
                executor.submit(search_chunk, chunk): chunk[0]
                for chunk in chunks
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as error:
                    print(f"Worker error: {error}", flush=True)
                    continue

                completed_chunks += 1

                if result is not None:
                    found = result
                    index, username, password = result

                    print("\n[+] MATCH FOUND!", flush=True)
                    print(f"Username: {username}", flush=True)
                    print(f"Password: {password}", flush=True)
                    print(
                        f"Dictionary position: {index + 1}",
                        flush=True,
                    )

                    with open(
                        OUTPUT_FILE, "w", encoding="utf-8"
                    ) as f:
                        f.write(f"{username},{password}\n")

                    print(f"Saved to: {OUTPUT_FILE}", flush=True)

                    stop_event.set()

                    # Cancel tasks that have not started.
                    for pending in futures:
                        if pending is not future:
                            pending.cancel()

                    break

                if completed_chunks % 20 == 0:
                    elapsed = time.perf_counter() - start_time
                    print(
                        f"Completed chunks: "
                        f"{completed_chunks}/{len(chunks)}"
                        f" | elapsed: {elapsed:.1f}s",
                        flush=True,
                    )

    # Verify the recovered credentials with the actual login script.
    if found is not None:
        _, username, password = found

        if os.path.isfile(LOGIN_SCRIPT):
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        LOGIN_SCRIPT,
                        username,
                        password,
                    ],
                    cwd=BASE_DIR,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                output = (result.stdout + result.stderr).strip()

                print("\n--- Login Verification ---", flush=True)
                print(
                    output if output else
                    f"Login script exit code: {result.returncode}",
                    flush=True,
                )

            except (OSError, subprocess.TimeoutExpired) as error:
                print(
                    f"Could not run login verification: {error}",
                    flush=True,
                )
        else:
            print(
                "LoginTemplate.py was not found; "
                "check the script path.",
                flush=True,
            )

    else:
        print(
            "\nNo matching credentials found in the dictionary.",
            flush=True,
        )

    elapsed = time.perf_counter() - start_time
    print(f"\nExecution Time: {elapsed:.4f} seconds", flush=True)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()