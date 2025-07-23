# config.py
import os

# Получаем абсолютный путь к папке database
basedir = os.path.abspath(os.path.dirname(__file__))
database_path = os.path.join(basedir, 'database', 'marketplace.db')

# Создаем папку database если её нет
database_dir = os.path.dirname(database_path)
if not os.path.exists(database_dir):
    os.makedirs(database_dir)


class Config:
    # ВАЖНО: Измените SECRET_KEY на случайный, сильный ключ в рабочей среде!
    # Используйте, например, os.urandom(24) или secrets.token_hex(32)
    SECRET_KEY = 'your-secret-key-change-in-production'

    SQLALCHEMY_DATABASE_URI = f'sqlite:///{database_path}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ВАЖНО: Измените JWT_SECRET_KEY на случайный, сильный ключ в рабочей среде!
    # Используйте, например, os.urandom(32) или secrets.token_hex(32)
    JWT_SECRET_KEY = 'your-jwt-secret-key-change-in-production'
