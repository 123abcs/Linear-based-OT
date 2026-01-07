import csv
import pickle
import random
import socket
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import wraps, partial
from multiprocessing import Pool

import gmpy2
import numpy as np
import rsa
import os

from Cryptodome.PublicKey import RSA
from sympy import Matrix

# from solve1 import Solution
from sss import Solution as sSolution
from mod_solver import solve_modular_linear_system


# 异或函数，全局调用
def str_xor(s: str, k: str):
    k = (k * (len(s) // len(k) + 1))[0:len(s)]
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s, k))


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


time_lists = []


def time_it(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        t1 = time.perf_counter()
        res = func(*args, **kwargs)
        t2 = time.perf_counter()
        print(f'{func}的运行时间：', t2 - t1)
        time_lists.append(t2 - t1)
        return res

    return wrapper


class Bob:
    def __init__(self, N, k):
        self.N = N
        self.k = k
        self.b = []

    @time_it
    def is_rank_equal(self, matrix):
        temp = []
        for c in matrix:
            temp.append(c[0:-1])
        rank_of_M = np.linalg.matrix_rank(temp)
        return rank_of_M == self.N - self.k

    @time_it
    def bob_gen_AX(self, public_key):
        self.e = public_key[1]
        self.n = public_key[0]
        self.lists, temp = [], []
        for i in range(self.N - self.k):
            for j in range(self.N):
                a = random.randint(1, 20)
                temp.append(a)
            btemp = gmpy2.mod(self.n - random.randint(2 ** 127, 2 ** 128), self.n)
            temp.append(btemp)
            self.b.append(btemp)
            self.lists.append(temp)
            temp = []
        np.array(self.lists)
        return self.lists

    @time_it
    def bob_message_packaging(self, enc_ms):
        enc_ms2 = []
        self.bob_key = str(random.randint(0, 9)) * 256
        for m in enc_ms:
            e_m = str_xor(m, self.bob_key)
            enc_ms2.append(e_m)
        self.choices = random.sample([i for i in range(self.N)], self.k)  # 随机选取k个变量
        self.choices = sorted(self.choices)
        self.choices_copy = set(self.choices)
        self.unknown_indices = [i for i in range(self.N) if i not in self.choices_copy]
        self.new_messages = []
        temp = enc_ms2[random.choices(self.unknown_indices)[0]]
        # if len(self.unknown_indices) > 1:
        #     temp = enc_ms2[random.choices(self.unknown_indices)]
        #     for c_index in range(len(self.unknown_indices)):
        #         if c_index == 0:
        #             continue
        #         temp = str_xor(temp, enc_ms2[self.unknown_indices[c_index]])
        for c in self.choices:
            self.new_messages.append(enc_ms2[c])
        self.choices = [i for i in range(len(self.choices))]
        self.choices_copy = set(self.choices)
        self.unknown_indices = [self.choices[-1] + 1]
        self.N = self.k + 1
        return self.new_messages + [temp]

    @time_it
    def bob_enc_random_number(self):
        self.r = [random.randint(2 ** 127, 2 ** 128) for _ in range(self.k)]
        self.C_known = [gmpy2.powmod(x, self.e, self.n) for x in self.r]
        A_known = np.array(self.lists)[:, self.choices]
        A_unknown = np.array(self.lists)[:, self.unknown_indices]
        known_vector = [0] * self.N
        for index, value in zip(self.choices, self.C_known):
            known_vector[index] = value
        for i in range(len(A_known)):
            minus = 0
            for j in range(len(self.C_known)):
                minus += A_known[i][j] * self.C_known[j]
            self.b[i] -= minus
        A_unknown_sympy = Matrix(A_unknown)
        b_adjusted_sympy = Matrix(self.b)
        b_adjusted_sympy = b_adjusted_sympy.applyfunc(lambda x: x % self.n)
        ssolution = sSolution(A_unknown_sympy, b_adjusted_sympy, self.n)
        solutions = ssolution.solve_modular_linear_system(A_unknown_sympy, b_adjusted_sympy, self.n)
        results = []
        for k, v in solutions.items():
            results.append(v)
        solution_all = known_vector
        for i, val in zip(self.unknown_indices, results):
            solution_all[i] = val
        self.C = solution_all
        return self.C

    @time_it
    def bob_dec_message(self, mess_enc):
        C_lists = []
        for i in range(len(self.C)):
            C_lists.append(self.C[i])
        ms, t = [], 0
        for i in range(len(mess_enc)):
            if i in self.choices_copy:
                C_lists[i] = self.r[t]
                t += 1
                ms.append(str_xor(mess_enc[i], str(hash(C_lists[i]))))
        mms = []
        for m in ms:
            t = str_xor(m, self.bob_key)
            mms.append(t)
        print(mms)


def main(N, k):
    t1 = time.perf_counter()
    bob = Bob(N, k)
    ip_port = ('127.0.0.1', 48524)
    sk = socket.socket()
    sk.connect(ip_port)
    sk.sendall('I am bob, requesting communication, executing the protocol.....\n'.encode())
    print(sk.recv(1024).decode())

    len_sel_enc_ms = int(sk.recv(1024000).decode())
    sk.sendall(f'OK,I(bob) have received len_sel_enc_ms,it\'s {len_sel_enc_ms}.'.encode())
    enc_ms = pickle.loads(sk.recv(len_sel_enc_ms))

    new_messages = bob.bob_message_packaging(enc_ms)
    serialized_new_messages = pickle.dumps(new_messages)
    sk.sendall(str(len(serialized_new_messages)).encode())
    print(sk.recv(1024).decode())
    sk.sendall(serialized_new_messages)

    len_serialized_public_key = int(sk.recv(2048).decode())
    sk.sendall(f'OK,I(bob) have received len_serialized_public_key,it\'s {len_serialized_public_key}.'.encode())
    public_key = pickle.loads(sk.recv(len_serialized_public_key))
    t2 = time.perf_counter()
    lists = bob.bob_gen_AX(public_key=public_key)
    while not bob.is_rank_equal(lists):
        lists = bob.bob_gen_AX(public_key=public_key)
    t3 = time.perf_counter()
    serialized_lists = pickle.dumps(lists)
    sk.sendall(str(len(serialized_lists)).encode())
    print(sk.recv(1024).decode())
    sk.sendall(serialized_lists)

    enc_random = bob.bob_enc_random_number()
    serialized_enc_random = pickle.dumps(enc_random)
    sk.sendall(str(len(serialized_enc_random)).encode())
    print(sk.recv(1024).decode())
    sk.sendall(serialized_enc_random)
    len_mess_enc = int(sk.recv(1024000).decode())
    sk.sendall(f'OK,I(bob) have received len_mess_enc,it\'s {len_mess_enc}.'.encode())
    mess_enc = sk.recv(len_mess_enc).decode().split('#')
    print(bob.choices)
    bob.bob_dec_message(mess_enc)
    t4 = time.perf_counter()
    len_time_lists_alice = int(sk.recv(1024000).decode())
    sk.sendall(f'OK,I(bob) have received len_time_lists_alice,it\'s {len_time_lists_alice}.'.encode())
    time_lists_alice = sk.recv(len_time_lists_alice).decode().split()
    time_lists_alice = [float(item) for item in time_lists_alice]
    t5 = time.perf_counter()
    return t3 - t2, t5 - t4, time_lists_alice, len_serialized_public_key, len(serialized_lists), len(
        serialized_enc_random), len_mess_enc, t4 - t1 - t3 + t2


if __name__ == "__main__":
    # t1 = time.perf_counter()
    tt, ss = 0, 0
    N, k = 1024, 512
    time_lists_alice = []
    for _ in range(1):
        t, t0, time_lists_alice, a, b, c, d, alltime = main(N, k)
        tt += alltime
        ss += a+b+c+d
    # t2 = time.perf_counter()
    print('总时间：', tt/1)
    if N == 30000:
        filename = '1_rsa_opt_k-out-of-n_ot30000.csv'
    elif N == 256:
        filename = '1_rsa_opt_k-out-of-n_ot256.csv'
    else:
        if k == 1:
            filename = '1_rsa_opt_k-out-of-n_ot2_1.csv'
        else:
            filename = '1_rsa_opt_k-out-of-n_ot2_2.csv'
    with open(filename, 'a+', encoding='utf-8', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(
            [N, k, tt/1, time_lists[2], time_lists[3], time_lists_alice[0],
             time_lists_alice[1], time_lists_alice[2], time_lists_alice[3], ss/1, 16])
