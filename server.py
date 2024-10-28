import os
import re
from db import DB
from md4 import MD4
from rsa import RSA
import mysql.connector
from flask import Flask, request, jsonify, session


class Server:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = os.urandom(24)
        self.setup_routes()

    def setup_routes(self):
        self.app.before_request(self.before_request)
        self.app.route('/register', methods=['POST'])(self.register)
        self.app.route('/login', methods=['POST'])(self.login)
        self.app.route('/key', methods=['GET'])(self.send_key)

    def run(self, debug=False, ssl_context=('cert.pem', 'key.pem')):
        self.app.run(debug=debug, ssl_context=ssl_context)

    @staticmethod
    def is_valid_username(user_name):
        return bool(re.match(r"^[a-zA-Z- ]{1,128}$", user_name))

    @staticmethod
    def is_valid_login(user_login):
        return bool(re.match(r"^[a-zA-Z0-9_]{3,30}$", user_login))

    @staticmethod
    def is_valid_password(password):
        return bool(re.match(r"^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&-+=()])(?=\S+$).{8,20}$", password))

    @staticmethod
    def send_key():
        rsa = RSA()
        session["private_key"] = rsa.private_key
        return jsonify({"key": rsa.public_key}), 200

    @staticmethod
    def before_request():
        if not request.is_secure:
            return jsonify({"status": "Please use HTTPS"}), 403

    def login(self):
        data = request.json
        encrypted_login = data.get('login')
        encrypted_password = data.get('password')
        if not all([encrypted_login, encrypted_password]):
            return jsonify({"status": "Missing required fields"}), 400

        private_key = session.get('private_key')

        user_login = RSA.decrypt(private_key, encrypted_login)
        user_password = RSA.decrypt(private_key, encrypted_password)

        if not self.is_valid_login(user_login) or not self.is_valid_password(user_password):
            return jsonify({"status": "Login failed"}), 400

        try:
            salt = DB().get_salt(user_login)
        except TypeError as err:
            return jsonify({"status": str(err)}), 401
        except mysql.connector.Error as err:
            return jsonify({"status": str(err)}), 500

        hashed_password = MD4(user_password.encode('utf-8') + salt).hexdigest()
        name = DB().login(user_login, hashed_password)
        if name:
            return jsonify({"status": f"Login successful. Hello, {name}"}), 200
        else:
            return jsonify({"status": "Login failed"}), 401

    def register(self):
        data = request.json
        encrypted_name = data.get('name')
        encrypted_login = data.get('login')
        encrypted_password = data.get('password')
        if not all([encrypted_name, encrypted_login, encrypted_password]):
            return jsonify({"status": "Missing required fields"}), 400

        private_key = session.get('private_key')

        user_name = RSA.decrypt(private_key, encrypted_name)
        user_login = RSA.decrypt(private_key, encrypted_login)
        user_password = RSA.decrypt(private_key, encrypted_password)

        if not self.is_valid_username(user_name):
            return jsonify({"status": "Invalid Username"}), 400
        if not self.is_valid_login(user_login):
            return jsonify({"status": "Invalid Login"}), 400
        if not self.is_valid_password(user_password):
            return jsonify({"status": "Invalid Password"}), 400

        salt = os.urandom(16)
        hashed_password = MD4(user_password.encode("utf-8") + salt).hexdigest()
        DB().register(user_name, user_login, hashed_password, salt)
        return jsonify({"status": "User registered successfully"}), 201