import time
from functools import wraps

import gmpy2
from sympy import Matrix, symbols, solve_linear_system, mod_inverse
import numpy as np
from gmpy2 import mpz


def time_it(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        t1 = time.perf_counter()
        res = func(*args, **kwargs)
        t2 = time.perf_counter()
        print(f'{func}的运行时间：', t2 - t1)
        return res

    return wrapper


class Solution(object):
    def __init__(self, A, b, N):
        self.A = A
        self.b = b
        self.N = N

    @time_it
    def solve_modular_linear_system(self, A, b, N):
        # 确保 A 和 b 是 sympy 的 Matrix 对象
        if not isinstance(A, Matrix):
            A = Matrix(A)
        if not isinstance(b, Matrix):
            b = Matrix(b)
        # 确保 b 是列向量
        b = b.reshape(len(b), 1)
        # 将 b 转换为 mod N 下的向量
        b = b.applyfunc(lambda x: x % N)
        # 构建增广矩阵 [A | b]
        augmented_matrix = A.row_join(b)
        # 定义符号变量，根据 A 的列数（变量个数）创建
        x = symbols(f'x1:{A.cols + 1}')
        # 求解增广矩阵下的线性方程组 Ax = b mod N
        solutions = solve_linear_system(augmented_matrix, *x, modulus=N)
        if not solutions:
            return '无解'
        positive_solutions = {}
        for var, sol in solutions.items():
            sol = sol % N  # 确保解在模 N 下
            if sol > 0:
                positive_solutions[var] = sol
        if len(positive_solutions) == len(solutions):
            return positive_solutions
        else:
            return "没有全正的解"


# 示例用法
if __name__ == '__main__':
    # 定义矩阵 A 和向量 b
    A = Matrix([
        [1, 3, 5],
        [2, 5, 11],
        [3, 5, 7]
    ])
    b = Matrix([
        [2 ** 126 + 4],
        [2 ** 127 + 3],
        [2 ** 128 + 2]
    ])

    # 定义模数 N
    N = 2 ** 129
    solution = Solution(A,b,N)
    # 调用函数求解
    solutions = solution.solve_modular_linear_system(A, b, N)
    results = []
    for k, v in solutions.items():
        results.append(v)
        print(k, '=', v)

    for i in range(len(A) // len(b)):
        tmp = 0
        for j in range(len(b)):
            tmp += A[3 * i + j] * results[j]
        if tmp % N != b[i]:
            print('验证失败！')
        else:
            print('验证成功！')
