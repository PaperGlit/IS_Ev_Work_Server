import time
import base64
import mysql.connector


class DB:
    def __init__(self, host="localhost", user="root", passwd="root", db="is_ev_db"):
        self.host = host
        self.user = user
        self.passwd = passwd
        self.db = db
        self.conn = None
        self.connect()

    def connect(self):
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                passwd=self.passwd,
                database=self.db
            )
            if self.conn.is_connected():
                print("Connected to MySQL database")
        except mysql.connector.Error as err:
            print(f"An error occurred during connection: {err}")
            time.sleep(10)
            self.connect()

    def reconnect(self):
        if not self.conn or not self.conn.is_connected():
            print("Reconnecting to the database...")
            self.connect()

    def register(self, name, login, password, salt):
        self.reconnect()
        cursor = self.conn.cursor()
        salt = base64.b64encode(salt).decode('utf-8')
        sql = "INSERT INTO users VALUES (NULL, %s, %s, %s, %s)"
        val = (name, login, password, salt)
        try:
            cursor.execute(sql, val)
            self.conn.commit()
            print(f"An account with ID {cursor.lastrowid} has been registered successfully.")
        except mysql.connector.errors.IntegrityError:
            self.conn.rollback()
            print(f"Error: user login \"{login}\" already exists")
        except mysql.connector.Error as err:
            self.conn.rollback()
            print(f"An error occurred during registration: {err}")

    def login(self, login, password):
        self.reconnect()
        cursor = self.conn.cursor()
        sql = "SELECT username FROM users WHERE userlogin = %s AND userpassword = %s"
        val = (login, password)
        try:
            cursor.execute(sql, val)
            name = cursor.fetchone()[0]
            self.conn.commit()
            print("Successfully logged in.")
            return name
        except TypeError as err:
            print("Error: no account with these credentials was found")
        except mysql.connector.Error as err:
            print(f"An error occurred during login: {err}")
            return False

    def get_salt(self, login):
        self.reconnect()
        cursor = self.conn.cursor()
        sql = "SELECT usersalt FROM users WHERE userlogin = %s"
        val = (login,)
        try:
            cursor.execute(sql, val)
            salt = cursor.fetchone()[0]
            return base64.b64decode(salt)
        except mysql.connector.Error:
            print(f"An account with this username does not exist")
            return False