import mysql.connector
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE, DB_PORT
from utils.encryption import decrypt_password, verify_password


def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE,
            port=DB_PORT
        )
        if connection.is_connected():
            return connection
        else:
            return "Connection Error"
    except mysql.connector.Error as err:
        return err


def create_table_users(cursor):
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(255),
                        password VARCHAR(255),
                        crypto VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    except mysql.connector.Error as err:
        return err


# actulizar crypto
def insert_data_users(cursor, data):
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM users WHERE username = %s", (data['username'],))
        result = cursor.fetchone()
        if result[0] == 0:
            cursor.execute('''INSERT INTO users
                            (username, password, crypto)
                            VALUES (%s, %s, %s)''', (data['username'], data['password'], data['crypto']))
            return 'User created'
        else:
            return 'The user not available'
    except mysql.connector.Error as err:
        return err


def list_user(cursor, data):
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = %s", (data['username'],))
        user = cursor.fetchone()

        if user is None:
            return False

        passd = decrypt_password(user[2], user[3])

        if verify_password(hashed_password=data['password'], password=passd):
            return True
        else:
            return False

    except mysql.connector.Error as err:
        return err


def create_table_login(cursor):
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS login
                        (id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(255) UNIQUE,
                        password VARCHAR(255),
                        crypto VARCHAR(255),
                        token LONGTEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)''')
    except mysql.connector.Error as err:
        return err


def create_table_information_external(cursor):
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS information_external
                        (id INT AUTO_INCREMENT PRIMARY KEY,
                        fec_alta VARCHAR(255),
                        user_name VARCHAR(255),
                        codigo_zip VARCHAR(255),
                        credit_card_num TEXT,
                        credit_card_ccv TEXT,
                        cuenta_numero VARCHAR(255),
                        direccion TEXT,
                        geo_latitud VARCHAR(255),
                        geo_longitud VARCHAR(255),
                        color_favorito VARCHAR(255),
                        foto_dni TEXT,
                        ip TEXT,
                        auto TEXT,
                        auto_modelo TEXT,
                        auto_tipo TEXT,
                        auto_color TEXT,
                        cantidad_compras_realizadas INT,
                        avatar TEXT,
                        fec_birthday VARCHAR(255))''')
    except mysql.connector.Error as err:
        return err


def insert_data_login(cursor, data):
    try:
        sql = '''INSERT INTO login
                 (username, password, crypto, token)
                 VALUES (%s, %s, %s, %s)
                 ON DUPLICATE KEY UPDATE
                 password = VALUES(password),
                 crypto = VALUES(crypto),
                 token = VALUES(token)'''
        cursor.execute(
            sql, (data['username'], data['password'], data['crypto'], data['token']))
    except mysql.connector.Error as err:
        return err


def insert_data_external(cursor, encrypted_data):
    try:
        for user in encrypted_data:
            cursor.execute('''INSERT INTO information_external
                            (fec_alta, user_name, codigo_zip, credit_card_num, credit_card_ccv,
                            cuenta_numero, direccion, geo_latitud, geo_longitud, color_favorito,
                            foto_dni, ip, auto, auto_modelo, auto_tipo, auto_color,
                            cantidad_compras_realizadas, avatar, fec_birthday)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                           (user["fec_alta"], user["user_name"], user["codigo_zip"],
                            user["credit_card_num"], user["credit_card_ccv"], user["cuenta_numero"],
                            user["direccion"], user["geo_latitud"], user["geo_longitud"],
                            user["color_favorito"], user["foto_dni"], user["ip"],
                            user["auto"], user["auto_modelo"], user["auto_tipo"], user["auto_color"],
                            user["cantidad_compras_realizadas"], user["avatar"], user["fec_birthday"]))
    except mysql.connector.Error as err:
        return err


def list_crypto_login(cursor, username):
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = %s", (username,))
        return cursor.fetchone()
    except mysql.connector.Error as err:
        return err


def list_user_login_by_token(cursor, token):
    try:
        cursor.execute(
            "SELECT * FROM login WHERE token = %s", (token,))
        return cursor.fetchone()
    except mysql.connector.Error as err:
        return err


def list_information_external(cursor):
    try:
        cursor.execute("SELECT * FROM information_external")
        column_names = [desc[0] for desc in cursor.description]
        users = []
        for row in cursor.fetchall():
            user = {column_names[i]: row[i] for i in range(len(column_names))}
            users.append(user)
        return users
    except mysql.connector.Error as err:
        return []


def list_information_external_one(cursor, id):
    try:
        cursor.execute(
            "SELECT * FROM information_external WHERE id = %s", (id,))
        column_names = [desc[0] for desc in cursor.description]
        users = []
        for row in cursor.fetchall():
            user = {column_names[i]: row[i] for i in range(len(column_names))}
            users.append(user)
        return users
    except mysql.connector.Error as err:
        return []
