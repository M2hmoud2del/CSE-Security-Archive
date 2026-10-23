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

These scripts are intended for the supplied lab files and an authorized
educational environment only.
