

class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://scan_user:strongpassword@localhost/scan_results'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'change_this_to_a_random_secret_key'
