import os
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_PORT = os.getenv("DB_PORT")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
PASS = os.getenv("PASS")
USERNAME = os.getenv("USERNAME")
URL_CLIENT_EXTERNAL = os.getenv("URL_CLIENT_EXTERNAL")
SERVER_PORT = os.getenv("SERVER_PORT")
SERVER_HOST = os.getenv("SERVER_HOST")
