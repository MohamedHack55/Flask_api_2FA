import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/flask_2fa_api'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = 600