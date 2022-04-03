import random
from Crypto.Util.number import *
import hkdf

from Crypto.Cipher import AES

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

#Центр доверия T: генерируем случайные простые числа p и a
p = getPrime(5)
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

#Генерация параметров для стороны A
p_A = getPrime(10)
q_A = getPrime(10)
print("A выбрал два простых числа p_A = ", p_A, "и q_A = ", q_A)

e_A = getPrime(15)
print("A выбрал случайное целое e_A = ", e_A)

d_A_list = []
for i in range (1, (p_A-1)*(q_A-1)):
    if (e_A * i) % ((p_A-1)*(q_A-1)) == 1 :
        d_A_list.append(i)
print(d_A_list)
d_A = max(d_A_list)
print("A вычислил d_A = ", d_A)

#Генерация параметров для стороны B
p_B = getPrime(10)
q_B = getPrime(10)
print("B выбрал два простых числа p_B = ", p_B, "и q_B = ", q_B)

e_B = getPrime(15)
print("B выбрал случайное целое e_B = ", e_B)

d_B_list = []
for i in range (1, (p_B-1)*(q_B-1)):
    if (e_B * i) % ((p_B-1)*(q_B-1)) == 1 :
        d_B_list.append(i)
print(d_B_list)
d_B = max(d_B_list)
print("B вычислил d_B = ", d_B)

#Генерация открытых и закрытых ключей
SK_A = d_A
PK_A = e_A
print("Сторона A сгенерировала открытый ключ PK = ", PK_A, "и секретный ключ SK = ", SK_A)

b = getPrime(5)
SK_B = d_B
PK_B = e_B
print("Сторона B сгенерировала открытый ключ PK = ", PK_B, "и секретный ключ SK = ", SK_B)

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


salt = get_random_bytes(16)
K_B = HKDF(long_to_bytes((a**x)**y % p), 32, salt, SHA512, 1)
print(K_B)

# print(len(long_to_bytes(X)))
# print(len(K_B))
X_for_message = long_to_bytes(X) + (b'\x00')*(32 - len(long_to_bytes(X)))
Y_for_message = long_to_bytes(Y) + (b'\x00')*(32 - len(long_to_bytes(Y)))
# print("___________________________________________________________________________________")
# print(long_to_bytes(X))
# print(X_for_message)
# print(len(X_for_message))
# print("___________________________________________________________________________________")
# print(long_to_bytes(Y))
# print(Y_for_message)
# print(len(Y_for_message))

E_K_B = AES.new(K_B, AES.MODE_ECB)
M_1 = E_K_B.encrypt(K_B + X_for_message + Y_for_message)
print(M_1)
message_for_A = long_to_bytes(a**y % p) + (b'\x00')*(32 - len(long_to_bytes(a**y % p))) + M_1
print("A получил от B сообщение: ", message_for_A)

K_A = HKDF(long_to_bytes((a**y)**x % p), 32, salt, SHA512, 1)
print(K_A)

M_2 = E_K_B.decrypt(message_for_A)
print(M_2)
print(M_2[32:64])
if M_2[32:64] == K_B:
    print("Проверка подписи прошла успешно. Ключ принят.")
else:
    print("Ошибка.")

E_K_A = AES.new(K_A, AES.MODE_ECB)
M_3 = E_K_B.encrypt(K_A + X_for_message + Y_for_message)
print("B получил сообщение от A: ", M_3)

M_4 = E_K_B.decrypt(M_3)
print(M_4)
print(M_4[0:32])
if M_4[0:32] == K_A:
    print("Проверка подписи прошла успешно. Ключ принят.")
else:
    print("Ошибка.")

if K_A == K_B:
    print("Принят общий ключ K = ", K_A)
else:
    print("Ошибка")
    
