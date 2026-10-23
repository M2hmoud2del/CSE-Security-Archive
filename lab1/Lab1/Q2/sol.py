import hashlib
import os
import time

start_time = time.perf_counter()

usersHashedPWsfile = open("../.loginCheck", "r")
users=[]
hashed= {}

for row in usersHashedPWsfile:
    (user,hashedPW)=(row.strip('\n')).split(',')
    hashed[user]= hashedPW
    users.append(user)

usersHashedPWsfile.close()
passwords = open("./MostCommonPWs", "r")
passwordsList = passwords.read().splitlines()

passwords.close()

for user in users:
    if user == "Magdy":
        continue

    for password in passwordsList:
        hash=hashlib.sha256()
        hash.update(bytes(user+password,'utf-8'))
        for i in range(90000): 
            hash.update(hash.digest())
            guess=hash.hexdigest()

            if (guess) == hashed[user]:
                print ('Login successful.\n' + user + ':' + password)
                os.system("python ../LoginTemplate.py " + user + " " + password)
                break

print(f"Time taken: {time.perf_counter() - start_time:.2f} seconds")