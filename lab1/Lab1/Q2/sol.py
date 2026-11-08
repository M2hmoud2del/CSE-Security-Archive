import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

start_time = time.perf_counter()
directory = Path(__file__).resolve().parent

usersHashedPWsfile = open(directory.parent / ".loginCheck", "r")
users=[]
hashed= {}

for row in usersHashedPWsfile:
    (user,hashedPW)=(row.strip('\n')).split(',')
    hashed[user]= hashedPW
    users.append(user)

usersHashedPWsfile.close()
passwords = open(directory / "MostCommonPWs", "r")
passwordsList = passwords.read().splitlines()

passwords.close()
# print(passwordsList)
for user in users:

    for password in passwordsList:
        hash=hashlib.sha256()
        hash.update(bytes(user+password,'utf-8')  )  # for defenses against dictionary attack on the usersHashedPWs file
        for i in range(90000): 
            
            hash.update(hash.digest())   # prepend name and iterate
            
            guess=hash.hexdigest()

            if (guess) == hashed[user]:
                print ('Login successful.\n' + user + ':' + password)
                subprocess.run(
                    [sys.executable, str(directory.parent / "LoginTemplate.py"), user, password],
                    cwd=directory,
                    check=False,
                )
                break

print(f"Time taken: {time.perf_counter() - start_time:.2f} seconds")

