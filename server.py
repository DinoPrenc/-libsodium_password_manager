import base64
import json
import logging
import time
import sqlite3
import nacl.pwhash
import nacl.utils
import nacl.secret
import nacl.public
import nacl.exceptions

from urllib.parse import unquote
from flask import Flask, request
from utils import Utils

app = Flask(__name__)

SESSION_DURATION = 60 * 60  # SESSION DURATION IS ONE HOUR

SECRET_KEY = nacl.public.PrivateKey.generate()
PUBLIC_KEY = SECRET_KEY.public_key

utils = Utils(SECRET_KEY)


def query_db(query, multiple_items=False, db_name='test.db'):
    con = sqlite3.connect(db_name)
    cur = con.cursor()
    cur.execute(query)
    if multiple_items:
        results = cur.fetchall()
    else:
        results = cur.fetchone()
    con.close()
    return results


def insert_in_db(query, data, db_name='test.db'):
    con = sqlite3.connect(db_name)
    cur = con.cursor()
    cur.execute(query, data)
    con.commit()
    con.close()
    return cur.lastrowid


def check_user_session(session_key):
    key_time = int(session_key.split('|')[-1])
    if int(time.time()) - key_time > SESSION_DURATION:
        return False

    query = f'SELECT id FROM users where key=\'{session_key}\''
    result = query_db(query)
    if not result:
        return False
    if len(result) > 1:
        raise Exception("Error with data in db. Multiple users with same session key")
    return result[0]


def is_data_valid(required_fields, data):
    for field in required_fields:
        if not field in data:
            return False, f'Missing {field} field'
    return True, ''


def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False


@app.errorhandler(Exception)
def handle_exception(e):
    # pass through HTTP errors
    logging.error(e)
    return 'Internal server error', 500


@app.route('/handshake')
def handshake():
    client_public_key_b64 = request.headers.get('Public-Key')
    if not client_public_key_b64:
        return 'Pogreska prilikom uspostavljanja sigurne veze'

    client_public_key = base64.b64decode(client_public_key_b64)
    try:
        nacl.public.PublicKey(client_public_key)
    except Exception as e:
        logging.error(e)
        return 'Pogresan javni ključ'

    return base64.b64encode(PUBLIC_KEY._public_key).decode()


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    data = data.get('msg')
    client_key = base64.b64decode(request.headers.get('Public-Key'))
    if not client_key:
        return 'Pogreska prilikom uspostavljanja sigurne veze. Provjerite "Public-Key" header', 400
    data = json.loads(utils.decrypt_message(data, client_key))
    if 'username' not in data or 'password' not in data:
        return 'Nedostaju podaci', 400

    query = f'SELECT id, password FROM users WHERE username=\'{data["username"]}\''
    results = query_db(query)
    if not results:
        return 'User not found', 404
    id, password = results
    if not isinstance(password, bytes):
        password = password.encode()
    try:
        if not nacl.pwhash.verify(password, data['password'].encode()):
            return 'Kriva lozinka!', 400
    except nacl.exceptions.InvalidkeyError:
        return 'Kriva lozinka!', 400

    session_key = nacl.utils.random()
    session_key = base64.b64encode(session_key).decode('utf-8')
    session_key += '|' + str(int(time.time()))
    session_key = session_key.replace('/', '_')

    query = f'UPDATE users SET key=? WHERE username=?'
    data = (session_key, data['username'])
    insert_in_db(query, data)

    encrypted_msg = utils.encrypt_message({'id': id, 'key': session_key}, client_key)

    return {'msg': encrypted_msg}, 200


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    data = data.get('msg')
    client_key = base64.b64decode(request.headers.get('Public-Key'))
    if not client_key:
        return 'Pogreska prilikom uspostavljanja sigurne veze. Provjerite "Public-Key" header', 400
    data = json.loads(utils.decrypt_message(data, client_key))

    is_valid, msg = is_data_valid(['username', 'password', 'password_nd'], data)
    if not is_valid:
        return msg, 400

    if data['password'] != data['password_nd']:
        return "Lozinke se ne podudaraju", 400

    query = f'SELECT id FROM users WHERE username=\'{data["username"]}\''
    results = query_db(query)
    if results:
        return 'Korisnicko ime vec postoji', 400

    session_key = nacl.utils.random()
    session_key = base64.b64encode(session_key).decode('utf-8')
    session_key += '|' + str(int(time.time()))
    session_key = session_key.replace('/', '_')

    query = f'INSERT INTO users(username, password, key) VALUES(?, ?, ?)'
    data = (data['username'], nacl.pwhash.str(data['password'].encode()).decode(), session_key)
    insert_in_db(query, data)

    encrypted_msg = utils.encrypt_message({'key': session_key}, client_key)
    return {'msg': encrypted_msg}, 201


@app.route('/upload-file', methods=['POST'])
def upload_file():
    data = request.json
    data = data.get('msg')
    client_key = base64.b64decode(request.headers.get('Public-Key'))
    if not client_key:
        return 'Pogreska prilikom uspostavljanja sigurne veze. Provjerite "Public-Key" header', 400
    data = json.loads(utils.decrypt_message(data, client_key))

    is_valid, msg = is_data_valid(['session_key', 'file', 'db_name', 'password', 'password_nd'], data)
    if not is_valid:
        return msg, 400
    user_id = check_user_session(data['session_key'])
    if not user_id:
        return 'Molimo prijavite se', 401

    if data['password'] != data['password_nd']:
        return 'Lozinke se ne podudaraju', 400

    file = base64.b64decode(data['file'].encode()).decode()
    encrypted_file = utils.encrypt_file(file, data['password'])
    encrypted_file = base64.b64encode(encrypted_file).decode()

    query = f'INSERT INTO databases (data, user_id, db_name) VALUES(?, ?, ?)'
    db_data = (encrypted_file, user_id, data['db_name'])
    insert_in_db(query, db_data)

    return "Spremljeno"


@app.route('/<session_key>/list-files', methods=['GET'])
def list_files(session_key):
    session_key = unquote(session_key)
    user_id = check_user_session(session_key)
    if not user_id:
        return 'Molimo prijavite se', 401

    client_key = base64.b64decode(request.headers.get('Public-Key'))
    if not client_key:
        return 'Pogreska prilikom uspostavljanja sigurne veze. Provjerite "Public-Key" header', 400

    query = f'SELECT id,db_name FROM databases WHERE user_id=\'{user_id}\''
    results = query_db(query, multiple_items=True)
    if not results:
        return "Podaci nisu pronadeni", 404

    encrypted_msg = utils.encrypt_message({'files': results}, client_key)

    return {'msg': encrypted_msg}


@app.route('/<session_key>/get-file/<db_id>/<password>', methods=['GET'])
def get_file(session_key, db_id, password):
    session_key = unquote(session_key)
    client_key = base64.b64decode(request.headers.get('Public-Key'))
    if not client_key:
        return 'Pogreska prilikom uspostavljanja sigurne veze. Provjerite "Public-Key" header', 400

    user_id = check_user_session(session_key)
    if not user_id:
        return 'Molimo prijavite se', 401

    query = f'SELECT db_name,data FROM databases WHERE id=\'{db_id}\' AND user_id=\'{user_id}\''
    results = query_db(query)
    if not results:
        return 'Podaci nisu pronadeni', 404

    db_name, data = results
    data = base64.b64decode(data)
    password = utils.decrypt_message(password.replace('_', '/'), client_key)
    try:
        decrypted_data = utils.decrypt(data, password)
    except nacl.exceptions.CryptoError:
        return "Kriva lozinka", 400
    msg = utils.encrypt_message({'file': decrypted_data.decode()}, client_key)
    return {'msg': msg}, 200


@app.route('/edit/<db_id>', methods=['POST'])
def edit_file(db_id):
    data = request.json
    data = data.get('msg')
    client_key = base64.b64decode(request.headers.get('Public-Key'))
    if not client_key:
        return 'Pogreska prilikom uspostavljanja sigurne veze. Provjerite "Public-Key" header', 400
    data = json.loads(utils.decrypt_message(data, client_key))

    is_valid, msg = is_data_valid(['session_key', 'file', 'password'], data)
    if not is_valid:
        return msg, 400

    user_id = check_user_session(data['session_key'])
    if not user_id:
        return 'Molimo prijavite se', 401

    query = f'SELECT id FROM databases WHERE id=\'{db_id}\' AND user_id=\'{user_id}\''
    id = query_db(query)
    if not id:
        return 'Podaci nisu pronadeni', 404
    id = id[0]

    file = data.get('file')
    if not isinstance(file, str):
        try:
            file = json.dumps(file)
        except:
            return 'Krivi format datoteke', 400

    encrypted_file = utils.encrypt_file(file, data['password'])
    encrypted_file = base64.b64encode(encrypted_file).decode()

    query = f'UPDATE databases SET data=? WHERE id=?'
    data = (encrypted_file, id)
    insert_in_db(query, data)

    return 'Promjene spremljene', 200


if __name__ == '__main__':
    app.run()
