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
from shared.models import Device, Link, Function, DeviceFunction, EventLog, MonitoringData, PacketCapture, AssetDiscovery
from shared.config import Config

app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from different origins

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure database
app.config.from_object(Config)

# Initialise database
db.init_app(app)

# Import routes
from network_routes import network_routes

# Register routes
app.register_blueprint(network_routes)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

