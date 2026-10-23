import hashlib
import os
import time
import multiprocessing as mp
import torch

start_time = time.perf_counter()

usersHashedPWsfile = open("../.loginCheck", "r")
users = []
hashed = {}

for row in usersHashedPWsfile:
    (user, hashedPW) = (row.strip('\n')).split(',')
    hashed[user] = hashedPW
    users.append(user)

usersHashedPWsfile.close()

passwords = open("./LeakedPWs100k", "r", encoding='utf-8', errors='ignore')
passwordsList = passwords.read().splitlines()
passwords.close()

def check_password(user):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    for password in passwordsList:
        hash_obj = hashlib.sha256()
        hash_obj.update(bytes(str(user) + password, 'utf-8'))
        current_digest = hash_obj.digest()
        
        if device.type == 'cuda':
            digest_tensor = torch.tensor(list(current_digest), dtype=torch.uint8, device=device)
            for _ in range(90000):
                h = hashlib.sha256(bytes(digest_tensor.cpu().tolist()))
                digest_tensor = torch.tensor(list(h.digest()), dtype=torch.uint8, device=device)
            guess = hashlib.sha256(bytes(digest_tensor.cpu().tolist())).hexdigest()
        else:
            for _ in range(90000):
                current_digest = hashlib.sha256(current_digest).digest()
            guess = hashlib.sha256(current_digest).hexdigest()

        if guess == hashed[user]:
            print('Login successful.\n' + user + ':' + password)
            os.system("python3 ../LoginTemplate.py " + user + " " + password)
            break

if __name__ == '__main__':
    mp.set_start_method('spawn', force=True)
    
    num_gpus = torch.cuda.device_count()
    
    if num_gpus > 0:
        print(f"found {num_gpus} GPU(s). Running on GPU(s)...")
        with mp.Pool(processes=num_gpus) as pool:
            results = pool.map(check_password, users)
    else:
        num_cpus = mp.cpu_count()
        print(f"No GPUs found. Running on {num_cpus} CPU(s)...")
        with mp.Pool(processes=num_cpus) as pool:
            results = pool.map(check_password, users)

    print(f"Time taken: {time.perf_counter() - start_time:.2f} seconds")