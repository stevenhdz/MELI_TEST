from cryptography.fernet import Fernet
import bcrypt


def generate_key():
    key = Fernet.generate_key()
    return key


def encrypt_password(password, key):
    fernet = Fernet(key)
    msg = password.encode()
    encrypted_msg = fernet.encrypt(msg)
    return encrypted_msg


def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypt_data = fernet.decrypt(encrypted_password)
    return decrypt_data.decode()


def encrypt_data(data, sensitive_fields, key):
    cipher_suite = Fernet(key)
    encrypted_data = []
    for user in data:
        user_copy = user.copy()
        for field in sensitive_fields:
            if field in user_copy:
                user_copy[field] = cipher_suite.encrypt(
                    user_copy[field].encode())
        encrypted_data.append(user_copy)
    return encrypted_data


def decrypt_data(data, sensitive_fields, key):
    cipher_suite = Fernet(key)
    decrypted_data = []
    for user in data:
        user_copy = user.copy()
        for field in sensitive_fields:
            if field in user_copy:
                user_copy[field] = cipher_suite.decrypt(
                    user_copy[field]).decode()
        decrypted_data.append(user_copy)
    return decrypted_data


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def verify_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def criteria_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(char.isalpha() for char in password) and any(char.isupper() for char in password) and any(char.islower() for char in password)
