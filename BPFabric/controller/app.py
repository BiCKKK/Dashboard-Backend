import sys 
import os 

# Add project root to sys.path for module imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask
from flask_cors import CORS
import logging

# Importing database instance and application configuration
from shared import db   
from shared.config import Config

app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing (CORS) for the app

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure database using shared configuration
app.config.from_object(Config)

# Initialise database with the Flask app
db.init_app(app)

# Import controller routes
from controller_routes import controller_routes

# Register the controller blueprint with the Flask app
app.register_blueprint(controller_routes, url_prefix='/api')

if __name__ == '__main__':
    # Run the controller application on localhost with port 5050
    app.run(host="127.0.0.1", port=5050, debug=True, use_reloader=False)

