# app.py
import sys 
import os 

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask
from flask_cors import CORS
import logging

from shared import db
from shared.config import Config

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure database
app.config.from_object(Config)

# Initialise database
db.init_app(app)

from controller_routes import controller_routes

app.register_blueprint(controller_routes, url_prefix='/api')

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5050, debug=True, use_reloader=False)

