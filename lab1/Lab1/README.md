# Lab 1: Password Cracking Solutions

This directory contains Python solutions for Questions 1-3 of Lab 1. The
solutions demonstrate how password hashing, dictionary attacks, salting, and
key stretching affect the cost of password guessing.

## Requirements

- Python 3
- The shared `.loginCheck` file in this directory
- The password lists included in each question directory
- PyTorch for Q3 (`pip install torch`)

Run every command from the corresponding question directory. The programs
read `../.loginCheck` and invoke `../LoginTemplate.py` after finding a valid
password.

## Q1: Attack One User

### Goal

Recover the password for a single user using the `MostCommonPWs` dictionary.
The script currently targets the user `Magdy`.

### Method

For each candidate password, the script:

1. Concatenates the username and candidate password.
2. Calculates a SHA-256 digest.
3. Re-hashes the digest 90,000 times.
4. Compares the final hexadecimal digest with the value in `.loginCheck`.

This reproduces the hash construction used by `LoginTemplate.py` and shows a
targeted dictionary attack against one account.

### Run

```powershell
cd lab1/Lab1/Q1
python sol.py
```
### ث

When the password is found, the script prints the username and password and
calls the login checker.

### username :password
Magdy:password

### Execution time
Execution time: 3.72 seconds

## Q2: Attack All Users

### Goal

Recover passwords for every user using the `MostCommonPWs` dictionary.

### Method

Q2 uses the same hashing and comparison process as Q1, but loops through every
user listed in `.loginCheck`. For each user, it tries every candidate in
`MostCommonPWs` and performs the 90,000 additional SHA-256 iterations.

### Run

```powershell
cd lab1/Lab1/Q2
python sol.py
```

This approach is more expensive than Q1 because it repeats the dictionary
attack for all accounts.

### username :password
Magdy:password

Mostafa:1234567890

### Execution time

Time taken: 37.12 seconds


## Q3: Attack All Users with a Larger Dictionary

### Goal

Recover passwords for every user using the larger `LeakedPWs100k` password
list.

### Method

Q3 keeps the same username-plus-password hashing scheme and 90,000 repeated
hash operations, but uses the leaked 100k password list. To reduce the total
runtime, users are processed in parallel with Python multiprocessing.

The script checks for CUDA-enabled GPUs and reports the available GPU count.
The current implementation still performs the password-checking function with
Python and PyTorch is used for GPU detection; a machine without a GPU falls
back to a CPU process pool.

### Run

```powershell
cd lab1/Lab1/Q3
python sol.py
```

Expected startup messages include either `Running on GPU(s)...` or
`Running on CPU...`, followed by the number of detected devices or CPU cores.

### username :password
Magdy:password

Mostafa:1234567890

### Execution time

excution time:more than one hour

## Q4: Attack Using an Exposed Password File

### Goal
Recover the password of an additional user by using the exposed passwords listed in `Q4/PwnedPWfile`.

### Method
Q4 uses the exposed password file to identify a password reused by another user.

The script:

1. Reads the exposed passwords from `PwnedPWfile`.
2. Loads the user password hashes from `.loginCheck`.
3. Tests the candidate passwords against the users using the hashing process implemented in `LoginTemplate.py`.
4. Identifies the user whose password matches one of the exposed passwords.
5. Verifies the recovered credentials using the login checker.

This demonstrates the risk of password reuse when passwords are exposed in data breaches.

### Run
```bash
cd lab1/Lab1/Q4
python sol.py
```

### Results
```text
username :password
[Add the recovered username and password]
```

### Execution time
Execution time: [Add measured execution time]

---

## Q5: Attack Using Hashed Passwords and Two Random Digits

### Goal
Recover additional user credentials using the exposed hashed passwords in `Q5/HashedPWs`.

Users are assumed to have selected a password from `Q5/LeakedPWs100k` and appended two random digits to it.

### Method
Q5 uses the exposed hashed password file to reduce the search space and identify possible password matches.

The script:

1. Reads the exposed hashes from `HashedPWs`.
2. Loads the candidate passwords from `LeakedPWs100k`.
3. Appends every possible two-digit combination (`00`–`99`) to each candidate password.
4. Applies the required hashing process to the generated password candidates.
5. Compares the calculated hashes with the target user hashes in `.loginCheck`.
6. Reports the recovered credentials and verifies them using the login checker.

Appending two random digits creates 100 possible variants for each dictionary password, increasing the search space compared with a basic dictionary attack.

### Run
```bash
cd lab1/Lab1/Q5
python sol.py
```

### Results
```text
username :password
[Add the recovered username and password]
```

### Execution time
Execution time: [Add measured execution time]

---

## Q6: Attack Using Salted Password Hashes

### Goal
Recover the passwords of additional users using the salted password hashes stored in `Q6/SaltedPWs`.

Each target password is assumed to consist of a password from `Q6/LeakedPWs100k` followed by one random digit.

### Method
Q6 uses the salt associated with each user when testing password candidates.

The script:

1. Reads the usernames, salts, and salted hashes from `SaltedPWs`.
2. Loads candidate passwords from `LeakedPWs100k`.
3. Appends each possible digit (`0`–`9`) to every candidate password.
4. Concatenates the user's salt with each generated password candidate.
5. Calculates the hash using the hashing algorithm specified by the lab.
6. Compares the calculated hash with the corresponding stored salted hash.
7. Reports the recovered credentials when a match is found.

Since each user has a different salt, password candidates must be tested using the appropriate salt for each account. Salting helps prevent identical passwords from producing identical stored hashes and makes precomputed hash attacks less effective.

### Run
```bash
cd lab1/Lab1/Q6
python sol.py
```

### Results
```text
username :password
[Add the recovered username and password]
```

### Execution time
Execution time: [Add measured execution time]

---

## Notes
- Run each command from its corresponding question directory.
- Ensure that the required password lists and hash files are available.
- Use the exact hashing algorithm and input format specified by the lab.
- Record the actual execution time and recovered credentials after running each solution.
- These scripts are intended for the supplied lab files and an authorized educational environment only.

## Shared Hashing Process

The login checker and these solutions use the following process:

```text
digest = SHA256(username + password)
repeat 90,000 times:
    digest = SHA256(digest)
compare the final digest with .loginCheck
```

The repeated hashing increases the work required for each password guess. The
password lists demonstrate why common and leaked passwords remain vulnerable
when users choose weak passwords, even when key stretching is used.

## Files Used

| Question | Solution | Password list | Users |
| --- | --- | --- | --- |
| Q1 | `Q1/sol.py` | `Q1/MostCommonPWs` | `Q1/users` |
| Q2 | `Q2/sol.py` | `Q2/MostCommonPWs` | `Q2/users` |
| Q3 | `Q3/sol.py` | `Q3/LeakedPWs100k` | `Q3/users` |
| Q4 | `Q4/sol.py` | `Q4/PwnedPWfile` | `.loginCheck` |
| Q5 | `Q5/sol.py` | `Q5/LeakedPWs100k` | `.loginCheck`, `Q5/HashedPWs` |
| Q6 | `Q6/sol.py` | `Q6/LeakedPWs100k` | `Q6/SaltedPWs` |

These scripts are intended for the supplied lab files and an authorized
educational environment only.
