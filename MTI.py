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
alpha = max(j_list)
# print(a)

print("A и B известны параметры, установленные Центром Доверия T: p = ", p, "a = ", alpha)

#Генерация ключей
a = getPrime(5)
SK_A = a
PK_A = alpha**a % p
print("Сторона A сгенерировала открытый ключ PK = ", PK_A, "и секретный ключ SK = ", SK_A)

b = getPrime(5)
SK_B = b
PK_B = alpha**b % p
print("Сторона B сгенерировала открытый ключ PK = ", PK_B, "и секретный ключ SK = ", SK_B)

#Генерация случайного параметра со стороны A
x = getPrime(10)
print("A сгенерировал случайный параметр x = ", x)
m_AB = (alpha**x) % p
print("B получил m_AB = ", m_AB)

#Генерация случайного параметра со стороны B
y = getPrime(10)
print("B сгенерировал случайный параметр y = ", y)
m_BA = (alpha**y) % p
print("A получил m_BA = ", m_BA)

#Генерация общего секретного ключа
k_A = ((m_BA**a) * (PK_B**x)) % p
k_B = ((m_AB**b) * (PK_A**y)) % p
# print(k_A, k_B)

k_A_long = long_to_bytes(k_A)
# print(k_A_long)

k_B_long = long_to_bytes(k_B)
# print(k_B_long)

salt = get_random_bytes(16)
key_A = HKDF(k_B_long, 32, salt, SHA512, 2)
# print(key_A)

key_B = HKDF(k_B_long, 32, salt, SHA512, 2)
# print(key_B)

if key_A == key_B:
    print("A и B получили общий секретный ключ.")
else:
    print("Ошибка.")
    
