import os
from db import DB
from md4 import MD4
import mysql.connector
from flask import Flask, request, jsonify


app = Flask(__name__)

@app.before_request
def before_request():
    if not request.is_secure:
        request.url.replace("http://", "https://", 1)
        return jsonify({"status": "Please use HTTPS"}), 403

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user_name = data['name']
    user_login = data['login']
    user_password = data['password']
    salt = os.urandom(16)
    hashed_password = MD4(user_password.encode("utf-8") + salt).hexdigest()
    DB().register(user_name, user_login, hashed_password, salt)
    return jsonify({"status": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_login = data['login']
    user_password = data['password']
    try:
        salt = DB().get_salt(user_login)
    except TypeError as err:
        return jsonify({"status": err}), 401
    except mysql.connector.Error as err:
        return jsonify({"status": err}), 401
    hashed_password = MD4(user_password.encode('utf-8') + salt).hexdigest()
    name = DB().login(user_login, hashed_password)
    if name:
        return jsonify({"status": f"Login successful. Hello, {name}"}), 200
    else:
        return jsonify({"status": "Login failed"}), 401


if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))