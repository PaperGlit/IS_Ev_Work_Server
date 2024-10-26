import os
from db import DB
from md4 import MD4
from Crypto.Hash import MD4 as RMD4

def md4_hash(value, salt):
    hash_obj = RMD4.new()
    hash_obj.update(value.encode('utf-8') + salt)
    return hash_obj.hexdigest()

password = "143256"
salt = os.urandom(16)

real_md4 = md4_hash(password, salt)

md4_tested = MD4(password.encode('utf-8') + salt).hexdigest()
if real_md4 == md4_tested:
    print(f"Hashed value: {md4_tested}")
else:
    print("Hashed value is not the same")

DB().register("John", "johnjohnson", md4_tested, salt)

new_salt = DB().get_salt("johnjohnson")
md4_tested = MD4(password.encode('utf-8') + new_salt).hexdigest()

if DB().login("johnjohnson", md4_tested):
    print("Login successful")