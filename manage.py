from flask import Flask
from flask_migrate import Migrate
from shared import db
from shared.models import * # Import all models to ensure migrations include them 
from shared.config import Config

# Create a Flask application instance
app = Flask(__name__)

# Load configuration settings from the Config class
app.config.from_object(Config)

# Initialise the database with the application context
db.init_app(app)

# Set up Flask-Migrate for database migrations
migrate = Migrate(app, db)

# This file serves as the entry point for database management commands, such as migrations.
# To create or apply migrations, you can use Flask-Migrate commands with this setup.