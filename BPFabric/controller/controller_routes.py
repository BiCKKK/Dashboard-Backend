from flask import Blueprint, jsonify, current_app
from threading import Thread
import json
import logging

from controller import eBPFCLIApplication, install_functions

controller_routes = Blueprint('controller_routes', __name__)

@controller_routes.route('/start', methods=['POST'])
def start():
    try:
        app = current_app._get_current_object()
        if not hasattr(app, 'eBPFApp'):
            app.eBPFApp = eBPFCLIApplication(app).run()
            logging.info("Controller started.")
            return jsonify({'message': 'Controller started.'}), 200
        else: 
            logging.warning("Controller is already running.")
            return jsonify({'message': 'Controller is already running.'}), 200
    except Exception as e:
        logging.error(f"Failed to start the controller: {e}")
        return jsonify({'error': 'Failed to start the controller.'})

@controller_routes.route('/status', methods=['GET'])
def get_status():
    pass

@controller_routes.route('/install', methods=['POST'])
def install():
    pass