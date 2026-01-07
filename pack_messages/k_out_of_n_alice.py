import pickle
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from multiprocessing import Pool

import gmpy2
import numpy as np
import rsa
import os

from Cryptodome.PublicKey import RSA
from sympy import Matrix, Integer, Rational

# from solve1 import Solution
from sss import Solution as sSolution


# from rsa_decrypt import alice_dec_random_num


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


class Alice:
    def __init__(self, N, k):
        self.N = N
        self.k = k
        self.b = [0 for _ in range(N - k)]

    def generate_messages(self):
        m_list = []
        for i in range(self.N):
            m = f'this is message{i}'[-16:]
            m_list.append(m)
        return m_list

    @time_it
    def alice_gen_pk(self):
        key = RSA.generate(2048)
        self.sk2 = (key.p, key.q)
        self.sk3 = (gmpy2.mod(key.d, (key.p - 1)), gmpy2.mod(key.d, (key.q - 1)))
        self.pk = (key.n, key.e)
        self.sk = (key.n, key.d)
        self.q_inv = gmpy2.invert(key.q, key.p)
        return self.pk

    @time_it
    def alice_get_lists(self, lists):
        for i in range(len(lists)):
            self.b[i] = lists[i][-1]

    def process_message(self, args):
        ms, key = args
        return str_xor(ms, key)

    @time_it
    def alice_xor_messages(self, messages):
        enc_ms = []
        self.alice_key = str(random.randint(0, 9)) * 256
        # arg_list = [(ms, self.alice_key) for ms in messages]
        # processes = os.cpu_count()
        # with Pool(processes=processes) as pool:
        #     enc_ms = pool.map(self.process_message, arg_list, chunksize=50)
        # with ThreadPoolExecutor() as executor:
        #     enc_ms = list(executor.map(lambda ms: self.process_message(ms, self.alice_key), messages))
        for ms in messages:
            temp = str_xor(ms, self.alice_key)
            enc_ms.append(temp)
        return enc_ms

    @time_it
    def alice_dec_ms(self, new_ms):
        new_result = []
        for ms in new_ms:
            temp = str_xor(ms, self.alice_key)
            new_result.append(temp)
        self.N = self.k + 1
        return new_result

    def decrypt_single_c(self, args):
        c, p, q, d_p, d_q, q_inv = args
        if not isinstance(c, int):
            c = int(c)
        c_p = gmpy2.mod(c, p)
        c_q = gmpy2.mod(c, q)
        m_p = gmpy2.powmod(c_p, d_p, p)
        m_q = gmpy2.powmod(c_q, d_q, q)
        h = gmpy2.mod((m_p - m_q) * q_inv, p)
        m = m_q + h * q
        return m

    @time_it
    def alice_dec_random_num(self, C_res, lists):
        for i in range(self.N - self.k):
            temp = 0
            for j in range(self.N):
                temp += lists[i][j] * C_res[j]
            if temp % self.pk[0] != self.b[i]:
                print('temp:', temp % self.pk[0])
                print(f'self.b[{i}]:', self.b[i])
                raise Exception('方程组认证不通过协议终止!')
        p = self.sk2[0]
        q = self.sk2[1]
        d_p = self.sk3[0]
        d_q = self.sk3[1]
        q_inv = self.q_inv
        args_list = [(c, p, q, d_p, d_q, q_inv) for c in C_res]
        processes = os.cpu_count()
        # size = len(args_list)//(processes*4)
        with Pool(processes=processes) as pool:
            dec_c = pool.map(self.decrypt_single_c, args_list, chunksize=50)
        # dec_c = []
        # for c in C_res:
        #     if not isinstance(c, int):
        #         c = int(c)
        #     c_p = gmpy2.mod(c, p)
        #     c_q = gmpy2.mod(c, q)
        #     m_p = gmpy2.powmod(c_p, d_p, p)
        #     m_q = gmpy2.powmod(c_q, d_q, q)
        #     h = gmpy2.mod((m_p - m_q) * q_inv, p)
        #     m = m_q + h * q
        #     dec_c.append(m)
        return dec_c

    @time_it
    def alice_enc_message(self, nums, m_list):
        # m_list = self.generate_messages()
        enc_list = []
        for i in range(self.N):
            enc_m = str_xor(m_list[i], str(hash(nums[i])))
            enc_list.append(enc_m)
        return enc_list


def main(time_lists):
    N, k = 1024, 512
    # bob = Bob(N, k)
    alice = Alice(N, k)
    ip_port = ('127.0.0.1', 48524)
    sk = socket.socket()
    sk.bind(ip_port)
    print('等待客户端连接.......')
    sk.listen(5)
    conn, addr = sk.accept()
    if conn:
        print('连接成功！.......')
    print(conn.recv(1024).decode())
    conn.sendall('OK, I\'m alice, I will send the key, ready to get it! bob, OK?.......\n'.encode())
    messages = alice.generate_messages()

    enc_ms = alice.alice_xor_messages(messages)
    serialized_enc_ms = pickle.dumps(enc_ms)
    conn.sendall(str(len(serialized_enc_ms)).encode())
    print(conn.recv(1024).decode())
    conn.sendall(serialized_enc_ms)

    len_serialized_new_ms = int(conn.recv(1024000).decode())
    conn.sendall(f'OK,I(alice) have received len_serialized_new_ms,it\'s {len_serialized_new_ms}.'.encode())
    new_ms = pickle.loads(conn.recv(len_serialized_new_ms))

    new_result = alice.alice_dec_ms(new_ms)

    public_key = alice.alice_gen_pk()
    serialized_public_key = pickle.dumps(public_key)
    conn.sendall(str(len(serialized_public_key)).encode())
    print(conn.recv(1024).decode())
    conn.sendall(serialized_public_key)

    len_serialized_lists = int(conn.recv(1024000).decode())
    conn.sendall(f'OK,I(alice) have received len_serialized_lists,it\'s {len_serialized_lists}.'.encode())
    lists = pickle.loads(conn.recv(len_serialized_lists))
    alice.alice_get_lists(lists)

    len_sel_enc_random_str = int(conn.recv(1024000).decode())
    conn.sendall(f'OK,I(alice) have received len_sel_enc_random_str,it\'s {len_sel_enc_random_str}.'.encode())
    enc_random = pickle.loads(conn.recv(len_sel_enc_random_str))
    nums = alice.alice_dec_random_num(enc_random, lists)
    mess_enc = alice.alice_enc_message(nums, new_result)
    mess_enc_list = '#'.join(mess_enc)
    conn.sendall(str(len(mess_enc_list)).encode())
    print(conn.recv(1024).decode())
    conn.sendall(mess_enc_list.encode())
    time_lists = [str(item) for item in time_lists]
    time_lists_str = '\n'.join(time_lists)
    conn.sendall(str(len(time_lists_str)).encode())
    print(conn.recv(1024000).decode())
    conn.sendall(time_lists_str.encode())
    conn.close()


if __name__ == "__main__":
    while True:
        main(time_lists)
