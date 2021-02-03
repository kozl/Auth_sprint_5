import os
import string
from hashlib import md5
from typing import Generator, List, Dict
from itertools import product
from multiprocessing import Pool, Queue

from tqdm import tqdm

PASSWORD_CHARSET = string.digits + string.ascii_lowercase


def hashes_to_crack() -> Dict[str, str]:
    hashes = {}
    with open('hashes.txt') as f:
        for line in f:
            hashes[line.strip()] = None
    return hashes


def calculate_hash(password: str) -> str:
    password_hash = md5(password.encode()).hexdigest()
    return (password, password_hash)


def password_generator(charset: str = PASSWORD_CHARSET, length: int = 6) -> Generator[str, None, None]:
    gen_password_set = product(*([charset] * length))
    for password_set in gen_password_set:
        yield ''.join(password_set)


if __name__ == '__main__':
    results = hashes_to_crack()
    progress_bar = tqdm(total=len(results))
    with Pool(processes=os.cpu_count()) as pool:
        hash_generator = pool.imap(calculate_hash, password_generator(), chunksize=1000)
        hashes_cracked = 0
        for password, md5hash in hash_generator:
            if md5hash in results:
                progress_bar.update(1)
                results[md5hash] = password
                hashes_cracked += 1
            if hashes_cracked == len(results):
                break

    print()
    print("Results:")
    for h, p in results.items():
        print(f"hash: {h} password: {p}")
