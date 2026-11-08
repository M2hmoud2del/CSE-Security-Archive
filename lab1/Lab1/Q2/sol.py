import hashlib
import subprocess
import sys
import time
from multiprocessing import Pool
from pathlib import Path


def check_password(data):
    salt, expected, wordlist = data

    for word in wordlist:
        for number in range(10):
            password = word + str(number)
            digest = hashlib.sha256(
                (salt + password).encode()
            ).hexdigest()

            if digest == expected:
                return password

    return None


def main():
    begin = time.perf_counter()
    directory = Path(__file__).resolve().parent

    def data_file(name):
        # Prefer files beside this script, then search the repository parents.
        path = directory / name
        if path.is_file():
            return path

        for parent in (directory, *directory.parents):
            matches = list(parent.glob(name))
            if matches:
                return matches[0]
            matches = list(parent.rglob(name))
            if matches:
                return matches[0]

        raise FileNotFoundError(
            f"Could not find {name!r} beside the script or in its parent directories"
        )

    # Load password dictionary
    with open(data_file("LeakedPWs100k"), encoding="utf-8") as file:
        wordlist = [line.strip() for line in file]

    # Read stored credentials
    credentials = {}
    with open(data_file("SaltedPWs"), encoding="utf-8") as file:
        for line in file:
            if line.strip():
                username, salt, hashed_password = line.strip().split(",", 2)
                credentials[username] = (salt, hashed_password)

    # Read target usernames
    with open(data_file("users"), encoding="utf-8") as file:
        targets = [line.strip() for line in file if line.strip()]

    # Divide dictionary into smaller sections
    workers = min(8, len(wordlist))
    sections = [
        wordlist[i::workers]
        for i in range(workers)
    ]

    excluded = {"Magdy", "Mostafa", "Kamal", "Andrew"}

    for username in targets:

        if username in excluded or username not in credentials:
            continue

        salt, stored_hash = credentials[username]

        arguments = [
            (salt, stored_hash, section)
            for section in sections
        ]

        # Search using multiple processes
        with Pool(workers) as executor:
            matches = executor.map(check_password, arguments)

        password = None
        for result in matches:
            if result:
                password = result
                break

        if password is None:
            continue

        # Verify the discovered password
        process = subprocess.run(
            [
                sys.executable,
                str(directory.parent / "LoginTemplate.py"),
                username,
                password
            ],
            cwd=directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )

        if process.returncode != 0:
            raise RuntimeError(process.stderr)

        if "Login successful." in process.stdout:
            print(
                f"Found password for user {username}: {password}",
                flush=True
            )
            print(process.stdout.strip(), flush=True)

    elapsed = time.perf_counter() - begin
    print(f"Runtime: {elapsed:.6f} seconds")


if __name__ == "__main__":
    main()