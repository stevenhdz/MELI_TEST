from database.database import connect_to_database, update_crypto_token_user, create_table_information_external, list_information_external_one, list_user_login_by_token, insert_data_external, list_information_external, list_crypto_login, create_table_login, insert_data_login, user_default, create_table_users, insert_data_users, list_user
from utils.encryption import criteria_password, hash_password, decrypt_password, generate_key, encrypt_data, decrypt_data, encrypt_password
from config import JWT_SECRET_KEY, PASS, USERNAME, URL_CLIENT_EXTERNAL, SERVER_PORT, SERVER_HOST, ROLESADMIN, ROLESRHH
import requests
from flask_swagger import swagger
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import logging
import datetime

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 500  # 5 minutes
app.config['JWT_CSRF_METHODS'] = ['POST', 'GET']
app.config['JWT_ALGORITHM'] = 'HS512'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

jwt = JWTManager(app)

app.logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('monitoring.log')
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

cors = CORS(app, resources={
            r"/*": {"origins": ["*"]}
            }, methods=["GET", "POST"])

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute", "1 per second"],
    storage_uri="memory://",
)

key = generate_key()
current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
PAYLOAD_SIZE_LIMIT = 1024  # 1KB


HIDDEN_FIELDS = [
    "credit_card_num",
    "credit_card_ccv",
    "cuenta_numero",
    "foto_dni",
    "geo_latitud",
    "geo_longitud",
    "ip",
    "fec_alta",
]


SENSIBLE_FIELDS = [
    "credit_card_num",
    "credit_card_ccv",
    "cuenta_numero",
    "foto_dni",
    "geo_latitud",
    "geo_longitud",
    "ip",
    "fec_alta",
]


SENSIBLE_FIELDS_USER = [
]

SENSIBLE_FIELDS_RRHH = [
    "fec_alta",
]


def validate_params(required_params):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            data = request.get_json()
            missing_params = [
                param for param in required_params if param not in data]
            if missing_params:
                return jsonify({'error': f'Missing parameters: {", ".join(missing_params)}'}), 400
            return func(*args, **kwargs)
        return wrapper
    return decorator


def get_jwt_identity():
    return request.headers.get('Authorization').replace('Bearer ', '')


def information_external_hidden_data():
    try:
        app.logger.info(f'{current_time} - Start')
        response = requests.get(URL_CLIENT_EXTERNAL)
        data = response.json()
        encrypted_data = encrypt_data(data, HIDDEN_FIELDS, key)
        conn = connect_to_database()
        cursor = conn.cursor()
        insert_data_external(cursor, encrypted_data)
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        print(f'Error: {str(e)}')


@app.route('/v1/swagger')
def get_swagger():
    try:
        app.logger.info(f'{current_time} - Start Swagger')
        swag = swagger(app)
        swag['info']['version'] = '1.0'
        swag['info']['title'] = 'Challenge MELI'
        swag['info']['description'] = 'API for MELI Challenge'
        swag['host'] = f'{SERVER_HOST}:{SERVER_PORT}'
        swag['basePath'] = '/v1'
        return swag
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/v1/register', methods=['POST'])
@validate_params(['username', 'password'])
def register():
    """
    Register a new user.
    ---
    parameters:
      - name: username
        in: formData
        type: string
        required: true
        description: Username for registration
      - name: password
        in: formData
        type: string
        required: true
        description: Password for registration
    responses:
      200:
        description: User registered successfully
      400:
        description: Bad request
      500:
        description: Internal server error
    """
    try:
        app.logger.info(f'{current_time} - Register')

        if request.content_length is not None and request.content_length > PAYLOAD_SIZE_LIMIT:
            return jsonify({'error': 'Payload size exceeds limit'}), 400

        username = request.json.get('username')
        password = request.json.get('password')

        if criteria_password(password) is False:
            return jsonify({'error': 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number and one special character'}), 400

        conn = connect_to_database()
        cursor = conn.cursor()
        insert = insert_data_users(
            cursor, {'username': username, 'password': encrypt_password(password, key), 'crypto': key})
        conn.commit()
        conn.close()
        return jsonify({'message': insert}), 200
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/v1/login', methods=['POST'])
@validate_params(['username', 'password'])
def login():
    """
    Login a user.
    ---
    parameters:
      - name: username
        in: formData
        type: string
        required: true
        description: Username for login
      - name: password
        in: formData
        type: string
        required: true
        description: Password for login
    responses:
      200:
        description: User logged in successfully
      401:
        description: Invalid credentials
      500:
        description: Internal server error
    """
    try:
        app.logger.info(f'{current_time} - Login')

        if request.content_length is not None and request.content_length > PAYLOAD_SIZE_LIMIT:
            return jsonify({'error': 'Payload size exceeds limit'}), 400

        username = request.json.get('username')
        password = request.json.get('password')

        conn = connect_to_database()
        cursor = conn.cursor()

        access_token = create_access_token(identity=username)
        data = {
            'username': username,
            'password': encrypt_password(password, key),
            'crypto': key,
            'token': access_token
        }
        create_table_login(cursor)
        insert_data_login(cursor, data)

        hashed_password = hash_password(password)

        if not list_user(cursor, {'username': username, 'password': hashed_password}):
            return jsonify({'error': 'Invalid credentials'}), 401

        conn.commit()
        conn.close()

        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/v1/information/external', methods=['POST'])
@limiter.limit("10 per minute")
@jwt_required()
def get_users():
    """
    Get users.
    ---
    headers:
      - name: Authorization
        in: header
        type: string
        required: true
        description: JWT token
    responses:
      200:
        description: Users retrieved successfully
      400:
        description: Bad request
      401:
        description: Unauthorized
      500:
        description: Internal server error    
    """
    try:
        app.logger.info(f'{current_time} - Get users')

        if request.content_length is not None and request.content_length > PAYLOAD_SIZE_LIMIT:
            return jsonify({'error': 'Payload size exceeds limit'}), 400

        conn = connect_to_database()
        cursor = conn.cursor()
        users = list_information_external(cursor)
        get_token = get_jwt_identity()
        token = list_user_login_by_token(cursor, get_token)

        if not token:
            return jsonify({'error': 'Invalid token'}), 401

        crypto = list_crypto_login(cursor, token[1])
        passw = decrypt_password(crypto[2], crypto[3])
        encryptypassw = encrypt_password(passw, key)

        update = update_crypto_token_user(
            cursor, key, encryptypassw, crypto[1])

        if crypto[4] == 'admin':
            fields = SENSIBLE_FIELDS
        elif crypto[4] == 'rrhh':
            fields = SENSIBLE_FIELDS_RRHH
        else:
            fields = SENSIBLE_FIELDS_USER

        conn.commit()
        conn.close()
        if update:
            decrypted_users = decrypt_data(users, fields, crypto[3])
            return jsonify(decrypted_users), 200
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/v1/information/external/one', methods=['POST'])
@limiter.limit("10 per minute")
@jwt_required()
@validate_params(['id'])
def get_one_user():
    """
    Get one user.
    ---
    parameters:
      - name: id
        in: formData
        type: integer
        required: true
        description: ID of the user
    headers:
      - name: Authorization
        in: header
        type: string
        required: true
        description: JWT token
    responses:
      200:
        description: User retrieved successfully
      400:
        description: Bad request
      401:
        description: Unauthorized
      500:
        description: Internal server error
    """
    try:
        app.logger.info(f'{current_time} - Get one user')

        if request.content_length is not None and request.content_length > PAYLOAD_SIZE_LIMIT:
            return jsonify({'error': 'Payload size exceeds limit'}), 400

        conn = connect_to_database()
        cursor = conn.cursor()
        user = list_information_external_one(cursor, request.json.get('id'))
        get_token = get_jwt_identity()
        token = list_user_login_by_token(cursor, get_token)

        if not token:
            return jsonify({'error': 'Invalid token'}), 401

        crypto = list_crypto_login(cursor, token[1])
        passw = decrypt_password(crypto[2], crypto[3])
        encryptypassw = encrypt_password(passw, key)

        update = update_crypto_token_user(
            cursor, key, encryptypassw, crypto[1])

        if crypto[4] == 'admin':
            fields = SENSIBLE_FIELDS
        elif crypto[4] == 'rrhh':
            fields = SENSIBLE_FIELDS_RRHH
        else:
            fields = SENSIBLE_FIELDS_USER

        conn.commit()
        conn.close()
        if update:
            decrypted_user = decrypt_data(user, fields, crypto[3])
            return jsonify(decrypted_user), 200
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/v1/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout a user.
    ---
    responses:
      200:
        description: User logged out successfully
      400:
        description: Bad request
      401:
        description: Unauthorized
      500:
        description: Internal server error
    """
    try:
        current_user = get_jwt_identity()
        exp_time = get_jwt()["exp"]
        exp_time = datetime.timedelta(seconds=1)
        new_token = create_access_token(
            identity=current_user, expires_delta=exp_time)
        conn = connect_to_database()
        cursor = conn.cursor()
        user = list_user_login_by_token(cursor, current_user)
        data = {
            'username': user[1],
            'password': user[2],
            'crypto': key,
            'token': new_token
        }
        insert_data_login(cursor, data)
        conn.commit()
        conn.close()
        return jsonify({'message': 'User logged out'}), 200
    except Exception as e:
        app.logger.error(f'{current_time} - {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def page_not_found(error):
    app.logger.error(f'{current_time} - Page not found')

    if request.content_length is not None and request.content_length > PAYLOAD_SIZE_LIMIT:
        return jsonify({'error': 'Payload size exceeds limit'}), 400

    return {"error": "This page does not exist", "code": 404}, 404


@app.errorhandler(500)
def special_exception_handler(error):
    app.logger.error(f'{current_time} - Server error')

    if request.content_length is not None and request.content_length > PAYLOAD_SIZE_LIMIT:
        return jsonify({'error': 'Payload size exceeds limit'}), 400

    return {"error": "Error in the server", "code": 500}, 500


@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def user_defaults():
    conn = connect_to_database()
    cursor = conn.cursor()

    create_table_users(cursor)
    create_table_information_external(cursor)
    information_external_hidden_data()

    data = [
        (ROLESADMIN, encrypt_password(ROLESADMIN, key), key, ROLESADMIN),
        (ROLESRHH, encrypt_password(ROLESRHH, key), key, ROLESRHH),
    ]

    user_default(cursor, data)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    app.logger.info(f'{current_time} - Starting app')
    user_defaults()
    app.run(host=SERVER_HOST, port=SERVER_PORT, ssl_context=(
        "./cert/cert.pem", "./cert/key.pem"))
