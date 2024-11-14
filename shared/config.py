import os 

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'bikram123')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql+psycopg://bick:bikram@localhost:5432/DashboardDB')