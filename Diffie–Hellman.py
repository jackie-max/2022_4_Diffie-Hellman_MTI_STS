import random
from Crypto.Util.number import *
import hkdf

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

#Центр доверия T: генерируем случайные простые числа p и a
p = getPrime(10)
# a = getPrime(20)
# print(p)

a_list = []
for m in range(2, p-1):
    d = 2
    while m % d != 0:
        d += 1
    if d == m:
        a_list.append(m)
# print(a_list)

j_list = []
for i in a_list:
    if i**(p-1) % p == 1:
        for j in range (1, p-1):
            if i**j % p != 1:
                j_list.append(i)
    else:
        i = i + 1
a = max(j_list)
# print(a)

print("A и B известны параметры, установленные Центром Доверия T: p = ", p, "a = ", a)

#Генерация случайного параметра со стороны A
x = getPrime(5)
print("A сгенерировал случайный параметр x = ", x)
X = (a**x) % p
print("B получил X = ", X)

#Генерация случайного параметра со стороны B
y = getPrime(5)
print("B сгенерировал случайный параметр y = ", y)
Y = (a**y) % p
print("A получил Y = ", Y)

#Генерация общего секретного ключа со стороны A
k_A_1 = (Y**x) % p
k_A_2 = (a**y)**x % p
k_A_3 = a**(x*y) % p
# print(k_A_1, k_A_2, k_A_3)

if k_A_1 == k_A_2:
    if k_A_2 == k_A_3:
        k_A = k_A_1
        print("Общий секретный ключ k_A = ", k_A)
    else:
        print("Ошибка.")
else:
    print("Ошибка.")

k_A_long = long_to_bytes(k_A)
# print(k_A_long)

salt = get_random_bytes(16)
key_A = HKDF(k_A_long, 32, salt, SHA512, 2)
print(key_A)

#Генерация общего секретного ключа со стороны B
k_B_1 = (X**y) % p
k_B_2 = (a**x)**y % p
k_B_3 = a**(x*y) % p
# print(k_B_1, k_B_2, k_B_3)

if k_B_1 == k_B_2:
    if k_B_2 == k_B_3:
        k_B = k_B_1
        print("Общий секретный ключ k_B = ", k_B)
    else:
        print("Ошибка.")
else:
    print("Ошибка.")

k_B_long = long_to_bytes(k_B)
# print(k_B_long)

key_B = HKDF(k_B_long, 32, salt, SHA512, 2)
# print(key_B)

if key_A == key_B:
    print("A и B получили общий секретный ключ.")
else:
    print("Ошибка.")
