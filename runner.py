import os
import re
from db import DB
from rsa import RSA
from md4 import MD4
import mysql.connector
from flask import Flask, request, jsonify


rsa = RSA()

app = Flask(__name__)

@app.before_request
def before_request():
    if not request.is_secure:
        return jsonify({"status": "Please use HTTPS"}), 403

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    encoded_name = data['name']
    encoded_login = data['login']
    encoded_password = data['password']

    user_name = rsa.decrypt(encoded_name)
    user_login = rsa.decrypt(encoded_login)
    user_password = rsa.decrypt(encoded_password)

    if not is_valid_username(user_name):
        return jsonify({"status": "Invalid Username"}), 400
    if not is_valid_login(user_login):
        return jsonify({"status": "Invalid Login"}), 400
    if not is_valid_password(user_password):
        return jsonify({"status": "Invalid Password"}), 400

    salt = os.urandom(16)
    hashed_password = MD4(user_password.encode("utf-8") + salt).hexdigest()
    DB().register(user_name, user_login, hashed_password, salt)
    return jsonify({"status": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    encrypted_login = data['login']
    encrypted_password = data['password']
    user_login = rsa.decrypt(encrypted_login)
    user_password = rsa.decrypt(encrypted_password)

    if not is_valid_login(user_login) or not is_valid_password(user_password):
        return jsonify({"status": "Login failed"}), 400
    try:
        salt = DB().get_salt(user_login)
    except TypeError as err:
        return jsonify({"status": err}), 401
    except mysql.connector.Error as err:
        return jsonify({"status": err}), 500
    hashed_password = MD4(user_password.encode('utf-8') + salt).hexdigest()
    name = DB().login(user_login, hashed_password)
    if name:
        return jsonify({"status": f"Login successful. Hello, {name}"}), 200
    else:
        return jsonify({"status": "Login failed"}), 401

@app.route('/key', methods=['GET'])
def send_key():
    global rsa
    rsa = RSA()
    return jsonify({"key": rsa.public_key}), 200

def is_valid_username(user_name):
    return bool(re.match(r"^[a-zA-Z- ]{,128}$", user_name))

def is_valid_login(user_login):
    return bool(re.match("^[a-zA-Z0-9_]{3,30}$", user_login))

def is_valid_password(password):
    return bool(re.match("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&-+=()])(?=\\S+$).{8,20}$", password))

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))