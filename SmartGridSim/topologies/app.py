# app.py
import sys 
import os 

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
import logging
from mininet.clean import cleanup

from shared import db
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
app.register_blueprint(network_routes, url_prefix='/api')

# Initialise SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Import and initialise network_sim.py with socketio
import network_sim
network_sim.init_socketio(socketio)

# Ensure shutdown
import atexit

def shutdown():
    logging.info("Shutting down application...")
    network_sim.stop_network(app)
    cleanup()
    logging.info("Applicaiton shutdown complete.")

atexit.register(shutdown)

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5100, debug=True, use_reloader=False)

