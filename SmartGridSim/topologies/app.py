import sys 
import os 

# Add the project directory to the Python path
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
from network_routes import network_routes
import network_sim

app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from different origins

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure database
app.config.from_object(Config)

# Initialise database
db.init_app(app)

# Register routes
app.register_blueprint(network_routes, url_prefix='/api')

# Ensure shutdown or application exit
import atexit

def shutdown():
    """
    Handles application shutdown by stopping the network simulation and cleaning up resources.

    Actions:
        Stops the network simulation.
        Cleans up Mininet resources.

    Ctrl+C will stop everything. To run commands in Mininet console, this needs to be removed or changed as
    it will not only stop mininet command outputs but also shutdown flask application. 
    """
    logging.info("Shutting down application...")
    network_sim.stop_network(app)
    cleanup()
    logging.info("Applicaiton shutdown complete.")

atexit.register(shutdown)

if __name__ == '__main__':
    # Start the Flask application
    app.run(host='127.0.0.1', port=5100, debug=True, use_reloader=False)

