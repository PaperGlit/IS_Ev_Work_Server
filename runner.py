import mysql.connector
from md4 import MD4 as other_md4
from Crypto.Hash import MD4

def md4_hash(value):
    hash_obj = MD4.new()
    hash_obj.update(value.encode('utf-8'))  # Encode the string in UTF-8
    return hash_obj.hexdigest()  # Return the hexadecimal digest

# user_db = mysql.connector.connect(
#     host="localhost",
#     user="root",
#     passwd="root",
# )
#
# db_cursor = user_db.cursor()
#
# sql = "INSERT INTO is_ev_db.users VALUES (NULL, %s, %s, %s, %s)"
# val = ("John", "johnjohnson", "12345667", "1241416546")
# db_cursor.execute(sql, val)
#
# user_db.commit()
#
# print(db_cursor.rowcount, "record inserted.")
hashed_value = md4_hash("")
print("MD4 Hash:", hashed_value)
print(other_md4.hash(""))