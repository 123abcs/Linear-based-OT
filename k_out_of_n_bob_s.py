'''
4选2不经意传输协议，基于RSA和多元方程组，选取第一、二位置上的数字作为想要的消息，Alice为发送者，Bob为接受者
连翘
2024.7.19
北京，北京隐算科技有限公司
'''
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


# 异或函数，全局调用
def str_xor(s: str, k: str):
    k = (k * (len(s) // len(k) + 1))[0:len(s)]
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s, k))


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


# class Alice:
#     def __init__(self, N, k):
#         self.N = N
#         self.k = k
#         self.b = [0 for _ in range(N - k)]
#
#     @time_it
#     def alice_gen_pk(self):
#         key = RSA.generate(1024)
#         self.sk2 = (key.p, key.q)
#         self.sk3 = (gmpy2.mod(key.d, (key.p - 1)), gmpy2.mod(key.d, (key.q - 1)))
#         self.pk = (key.n, key.e)
#         self.sk = (key.n, key.d)
#         self.q_inv = gmpy2.invert(key.q, key.p)
#         return self.pk
#
#     @time_it
#     def alice_get_lists(self, lists):
#         for i in range(len(lists)):
#             self.b[i] = lists[i][-1]
#
#     @time_it
#     def alice_dec_random_num(self, C_res, lists):
#         for i in range(self.N - self.k):
#             temp = 0
#             for j in range(self.N):
#                 temp += lists[i][j] * C_res[j]
#             if temp % self.pk[0] != self.b[i]:
#                 print('temp:', temp % self.pk[0])
#                 print(f'self.b[{i}]:', self.b[i])
#                 raise Exception('方程组认证不通过协议终止!')
#         p = self.sk2[0]
#         q = self.sk2[1]
#         d_p = self.sk3[0]
#         d_q = self.sk3[1]
#         q_inv = self.q_inv
#         dec_c = []
#         for c in C_res:
#             if not isinstance(c, int):
#                 c = int(c)
#             c_p = gmpy2.mod(c, p)
#             c_q = gmpy2.mod(c, q)
#             m_p = gmpy2.powmod(c_p, d_p, p)
#             m_q = gmpy2.powmod(c_q, d_q, q)
#             h = gmpy2.mod((m_p - m_q) * q_inv, p)
#             m = m_q + h * q
#             # decc = gmpy2.powmod(c, self.sk[1], self.sk[0])
#             dec_c.append(m)
#         return dec_c
#
#     @time_it
#     def alice_enc_message(self, nums):
#         m_list = []
#         for i in range(self.N):
#             m = f'this is message{i}'
#             m_list.append(m)
#         enc_list = []
#         for i in range(self.N):
#             enc_m = str_xor(m_list[i], str(hash(nums[i])))
#             enc_list.append(enc_m)
#         return enc_list


class Bob:
    def __init__(self, N, k):
        self.N = N
        self.k = k
        self.b = []

    # def pack_messages(self, sym_messages):
    #     global k_messages, n_k_messages
    #     self.sym_m = sym_messages.copy()
    #     self.choices = random.sample([i for i in range(self.N)], self.k)  # 随机选取k个变量
    #     self.choices = sorted(self.choices)
    #     self.choices_copy = set(self.choices)
    #     self.unknown_indices = [i for i in range(self.N) if i not in self.choices_copy]
    #     k_messages = sym_messages[self.choices[0]]
    #     if self.k > 1:
    #         for i in range(1, self.k):
    #             k_messages = str_xor(k_messages, sym_messages[self.choices[i]])
    #     n_k = self.N - self.k
    #     n_k_messages = sym_messages[self.unknown_indices[0]]
    #     if n_k > 1:
    #         for i in range(1, n_k):
    #             n_k_messages = str_xor(n_k_messages, sym_messages[self.choices[i]])
    #     rand_key = str(random.randint(10 ** 616, 10 ** 617 - 1))
    #     k_messages = str_xor(k_messages, rand_key)
    #     n_k_messages = str_xor(n_k_messages, rand_key)
    #     self.choices, self.unknown_indices = [0], [1]
    #     return k_messages, n_k_messages

    @time_it
    def is_rank_equal(self, matrix):
        temp = []
        for c in matrix:
            temp.append(c[0:-1])
        rank_of_M = np.linalg.matrix_rank(temp)
        return rank_of_M == self.k

    @time_it
    def bob_gen_AX(self, public_key):
        # self.n1, self.k1 = 2, 1
        self.e = public_key[1]
        self.n = public_key[0]
        self.lists, temp = [], []
        for i in range(self.k):
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

    def compute_powmod(self, args):
        x, e, n = args
        return gmpy2.powmod(x, e, n)

    def compute_powmod_parallel(self, r_list, e, n, processes=None):
        if processes is None:
            processes = os.cpu_count()  # 默认使用 CPU 核心数
        args_list = [(x, e, n) for x in r_list]
        with Pool(processes=processes) as pool:
            results = pool.map(self.compute_powmod, args_list)
        return results

    @time_it
    def bob_enc_random_number(self):
        self.r = [random.randint(2 ** 127, 2 ** 128) for _ in range(self.N - 1)]
        self.C_unknown = [gmpy2.powmod(x, self.e, self.n) for x in self.r]
        # args_list = [(x, self.e, self.n) for x in self.r]
        # with Pool() as pool:
        #     self.C_known = pool.map(self.compute_powmod, args_list)
        self.choices = random.sample([i for i in range(self.N)], self.k)
        A_known = np.array(self.lists)[:, self.choices]
        self.choices_copy = set(self.choices)
        self.unknown_indices = [i for i in range(self.N) if i not in self.choices_copy]
        A_unknown = np.array(self.lists)[:, self.unknown_indices]
        unknown_vector = [0] * self.N
        for index, value in zip(self.unknown_indices, self.C_unknown):
            unknown_vector[index] = value
        for i in range(len(A_unknown)):
            minus = 0
            for j in range(len(self.C_unknown)):
                minus += A_unknown[i][j] * self.C_unknown[j]
            self.b[i] -= minus
        A_known_sympy = Matrix(A_known)
        b_adjusted_sympy = Matrix(self.b)
        b_adjusted_sympy = b_adjusted_sympy.applyfunc(lambda x: x % self.n)
        ssolution = sSolution(A_known_sympy, b_adjusted_sympy, self.n)
        solutions = ssolution.solve_modular_linear_system(A_known_sympy, b_adjusted_sympy, self.n)
        results = []
        for k, v in solutions.items():
            results.append(v)
        solution_all = unknown_vector
        for i, val in zip(self.choices, results):
            solution_all[i] = val
        self.C = solution_all
        return self.C

    @time_it
    def bob_dec_message(self, mess_enc, symm_mes_list):
        C_lists = []
        for i in range(len(self.C)):
            C_lists.append(self.C[i])
        ms_key, t = [], 0
        unknown_indices_copy = set(self.unknown_indices)
        for i in range(len(mess_enc)):
            if i in unknown_indices_copy:
                C_lists[i] = self.r[t]
                t += 1
                ms_key.append(str_xor(mess_enc[i], str(hash(C_lists[i]))))
        result = symm_mes_list[self.choices[0]]
        for item in ms_key:
            result = str_xor(result, item)
        print(result)


def main():
    N, k = 2, 1
    if k != 1:
        print('This is an 1-out-of-n protocol.')
        return
    t1 = time.perf_counter()
    bob = Bob(N, k)
    # alice = Alice(N, k)
    # public_key = alice.alice_gen_pk()
    ip_port = ('127.0.0.1', 48524)
    sk = socket.socket()
    sk.connect(ip_port)
    sk.sendall('I am bob, requesting communication, executing the protocol.....\n'.encode())
    print(sk.recv(1024).decode())
    # public_key = alice.alice_gen_pk()
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
    len_symm_mes_list = int(sk.recv(1024000).decode())
    sk.sendall(f'OK,I(bob) have received len_symm_mes_list,it\'s {len_symm_mes_list}.'.encode())
    symm_mes_list = sk.recv(len_symm_mes_list).decode().split('#')
    # alice.alice_get_lists(lists)
    enc_random = bob.bob_enc_random_number()
    # enc_random_str = '\n'.join([str(item) for item in enc_random])
    # serialized_enc_random = enc_random_str.encode()
    serialized_enc_random = pickle.dumps(enc_random)
    sk.sendall(str(len(serialized_enc_random)).encode())
    print(sk.recv(1024).decode())
    sk.sendall(serialized_enc_random)
    # nums = alice.alice_dec_random_num(enc_random, lists)
    # mess_enc = alice.alice_enc_message(nums)
    len_mess_enc = int(sk.recv(1024000).decode())
    sk.sendall(f'OK,I(bob) have received len_mess_enc,it\'s {len_mess_enc}.'.encode())
    mess_enc = sk.recv(len_mess_enc).decode().split('#')
    print(bob.choices)
    bob.bob_dec_message(mess_enc, symm_mes_list)
    t4 = time.perf_counter()
    len_time_lists_alice = int(sk.recv(1024000).decode())
    sk.sendall(f'OK,I(bob) have received len_time_lists_alice,it\'s {len_time_lists_alice}.'.encode())
    time_lists_alice = sk.recv(len_time_lists_alice).decode().split()
    time_lists_alice = [float(item) for item in time_lists_alice]
    t5 = time.perf_counter()
    return (N, k, t3 - t2, t5 - t4, time_lists_alice, len_serialized_public_key, len(symm_mes_list), len(serialized_lists),
            len(serialized_enc_random), len_mess_enc)


if __name__ == "__main__":
    t1 = time.perf_counter()
    N, k, t, t0, time_lists_alice, a0, a1, b, c, d = main()
    t2 = time.perf_counter()
    print('总时间：', t2 - t1 - t - t0)
    if k == 1:
        filename = '../1_rsa_opt_k-out-of-n_ot2_1.csv'
    else:
        filename = '../1_rsa_opt_k-out-of-n_ot2_2.csv'
    with open(filename, 'a+', encoding='utf-8', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(
            [N, k, t2 - t1 - t - t0, time_lists[2], time_lists[3], time_lists_alice[0],
             time_lists_alice[1], time_lists_alice[2], time_lists_alice[3], a0, a1, b, c, d, a0 + a1 + b +
             c + d, 16])
