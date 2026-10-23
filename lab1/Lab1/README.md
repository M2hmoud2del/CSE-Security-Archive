# Lab 1: Password Cracking Solutions

This repository contains Python solutions for Questions 1–6 of Lab 1. The exercises demonstrate dictionary attacks, password reuse, exposed password hashes, salting, and the effect of repeated hashing on password-guessing cost. The Q3 solution also implements the Bonus using multithreading.

> **Scope:** These scripts are intended only for the supplied lab files and an authorized educational environment.

## Requirements

- Python 3
- The shared `.loginCheck` file in the `Lab1` directory
- The question-specific password lists, user lists, and exposed password/hash files
- The lab's login checker (`LoginTemplate.py` or the supplied compiled login script), where required by the solution

Run each command from its corresponding question directory. The exact files read and verification steps depend on the question. Q3's Bonus uses Python's built-in `concurrent.futures.ThreadPoolExecutor`; PyTorch is not required for the multithreaded version described here.

---

## Q1: Attack One User

### Goal

Recover the password for the user `Magdy` using the `MostCommonPWs` dictionary.

### Method

For each candidate password, the script:

1. Concatenates the username and candidate password.
2. Initializes a SHA-256 hash with that value.
3. Performs the lab's 90,000 repeated hash-update operations.
4. Compares the final digest with the user's stored value in `.loginCheck`.

This is a targeted dictionary attack against one account.

### Run

```powershell
cd lab1/Lab1/Q1
python sol.py
```

### Result

| Username | Password |
|---|---|
| Magdy | `password` |

### Recorded execution time

`3.72 seconds`

---

## Q2: Attack All Users

### Goal

Recover passwords for users in `.loginCheck` using the `MostCommonPWs` dictionary.

### Method

Q2 applies the same hashing and comparison process as Q1 to multiple accounts. For each user, it tests the candidate passwords and compares the results against the stored hash.

### Run

```powershell
cd lab1/Lab1/Q2
python sol.py
```

### Results

| Username | Password |
|---|---|
| Magdy | `password` |
| Mostafa | `1234567890` |

### Recorded execution time

`37.12 seconds`

---

## Q3: Dictionary Attack with a Larger Password List

### Goal

Find an additional user's password using the larger `LeakedPWs100k` dictionary, excluding accounts already exposed in previous questions.

### Method

For each candidate password and target username, the script reproduces the hashing procedure used by the lab's login checker and compares the result against the corresponding stored hash in `.loginCheck`. The original login implementation starts with `SHA-256(username + password)` and then calls `h.update(h.digest())` 90,000 times before comparing the final digest.

### Bonus: Multiprocessing

The Q3 Bonus uses Python's `ProcessPoolExecutor` to perform the dictionary attack across multiple processes.

- The password dictionary `LeakedPWs100k` is divided into smaller batches.
- Multiple worker processes check password candidates against the target users' stored hashes concurrently.
- Each candidate is tested using the same hashing algorithm as the lab's login script, including 90,000 repeated SHA-256 hash updates.
- When a matching result is found, the program prints the username and password and saves the credentials to `results.txt`.
- The program attempts to verify the recovered credentials using the login checker supplied with the lab.
- The total execution time is measured and printed.

**Performance note:** Multiprocessing allows CPU-bound tasks to run in separate processes, potentially taking advantage of multiple CPU cores. The actual speedup depends on the number of available cores, process-management overhead, and the workload.

### Previously Exposed Credentials

These credentials were identified in earlier questions and are excluded from the search for an additional user.

| Username | Password |
|---|---|
| Magdy | `password` |
| Mostafa | `1234567890` |

### Run

```powershell
cd lab1/Lab1/Q3
python -u sol.py
```

### Recorded Execution Time

`More than one hour`

*This is the previously recorded runtime. Run the final multiprocessing implementation to obtain an updated measurement if needed.*


---

## Q4: Attack Using an Exposed Password File

### Goal

Find an additional user's credentials by checking passwords from `PwnedPWfile` against the lab's login hashes.

### Method

1. Read the exposed password entries from `PwnedPWfile`.
2. Load the target usernames and the hashes used by the lab's login checker.
3. Test the candidate passwords using the login checker's hashing procedure.
4. Report a matching username/password pair and verify it with the supplied login checker, where supported by the lab setup.

This exercise demonstrates the risk of password reuse after a password has been exposed.

### Run

```powershell
cd lab1/Lab1/Q4
python sol.py
```

### Result

| Username | Password |
|---|---|
| Kamal | `RizPbXsc` |

### Recorded execution time

`0.1690 seconds`

---

## Q5: Attack Using Hashed Passwords and Two Random Digits

### Goal

Find credentials for an additional user using `HashedPWs`. The password is assumed to be a word from `LeakedPWs100k` followed by two random digits.

### Method

1. Read the exposed username/hash records from `HashedPWs`.
2. Load candidate words from `LeakedPWs100k`.
3. Append every two-digit suffix from `00` through `99` to each candidate word.
4. Calculate and compare candidate hashes using the format specified for `HashedPWs`.
5. Report any matching credentials and verify the candidate with the supplied login checker when the lab's verification setup supports it.

Each dictionary word has 100 possible two-digit suffixes.

### Run

```powershell
cd lab1/Lab1/Q5
python sol.py
```

### Result

| Username | Password |
|---|---|
| Andrew | `1011199065` |

### Recorded execution time

`16.9839 seconds`

---

## Q6: Attack Using Salted Password Hashes

### Goal

Find an additional user's password from the salted records in `SaltedPWs`. The password is assumed to be a word from `LeakedPWs100k` followed by one random digit.

### Method

1. Read the username, salt, and hash fields from `SaltedPWs`.
2. Load candidate words from `LeakedPWs100k`.
3. Append each digit from `0` through `9` to each candidate word.
4. Combine the user's salt with each candidate password in the order specified by the lab, then calculate the hash.
5. Compare the calculated value with the salted hash for that user.
6. Report the matching username/password pair.

Each user's salt must be used for that user's candidate checks. Salting prevents identical passwords from automatically having identical stored hashes and makes precomputed hash tables less useful.

### Run

```powershell
cd lab1/Lab1/Q6
python sol.py
```

### Result

| Username | Password |
|---|---|
| Peter | `clearwater9` |

### Recorded execution time

`2.3887 seconds`

**Verification note:** Q6's `SaltedPWs` records use a different hash format from the shared `.loginCheck` file. A match in `SaltedPWs` should therefore be checked according to Q6's specified format; it should not automatically be described as verified by the generic login checker unless that checker is configured for the same scheme.

---

## Shared Login Hashing Procedure (Q1–Q4 where applicable)

The login checker initializes SHA-256 with the username followed by the candidate password, then repeatedly updates the hash object with its current digest:

```python
h = hashlib.sha256()
h.update((username + password).encode("utf-8"))

for _ in range(90000):
    h.update(h.digest())

final_digest = h.hexdigest()
```

The final digest is compared with the value stored in `.loginCheck`. This describes the lab's specific implementation; it is not equivalent to simply computing `SHA256(SHA256(...))` 90,000 times.

Q5 and Q6 use the formats in their own exposed hash files and should be implemented according to each question's specification.

---

## Files Used

| Question | Solution | Password list / exposed file | Other inputs |
|---|---|---|---|
| Q1 | `Q1/sol.py` | `Q1/MostCommonPWs` | `.loginCheck` |
| Q2 | `Q2/sol.py` | `Q2/MostCommonPWs` | `.loginCheck` |
| Q3 | `Q3/sol.py` | `Q3/LeakedPWs100k` | `Q3/users`, `.loginCheck` |
| Q4 | `Q4/sol.py` | `Q4/PwnedPWfile` | `Q4/users`, `.loginCheck` |
| Q5 | `Q5/sol.py` | `Q5/LeakedPWs100k`, `Q5/HashedPWs` | `Q5/users`, `.loginCheck` for login verification |
| Q6 | `Q6/sol.py` | `Q6/LeakedPWs100k`, `Q6/SaltedPWs` | `Q6/users` |

## Notes

- Run each solution from its corresponding question directory.
- Check that each question's required input files are present before running the script.
- Execution times above are recorded results from the described runs; timing can vary by hardware and implementation.
- Only report credentials as login-verified if the supplied login checker actually confirms them.
- Use these scripts only with the supplied lab files in an authorized educational environment.
