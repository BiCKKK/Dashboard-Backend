# app.py
import sys 
import os 

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask, jsonify, request
from flask_cors import CORS
from threading import Thread
import logging
import json
import datetime

from controller import eBPFCLIApplication, install_functions
from shared import db
from shared.models import Device, Function, DeviceFunction, EventLog, MonitoringData, PacketCapture, AssetDiscovery
from shared.config import Config

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure database
app.config.from_object(Config)

# Initialise database
db.init_app(app)

def start_controller():
    if not hasattr(app, 'eBPFApp'):
        app.eBPFApp = eBPFCLIApplication(app).run()
        logging.info("Controller started.")
    else:
        logging.warning("Controller is already running.")

@app.route('/start', methods=['POST'])
def start():
    # Start the controller in a separate thread to avoid blocking
    thread = Thread(target=start_controller)
    thread.start()
    return jsonify({'message': 'Controller started.'}), 200

@app.route('/status', methods=['GET'])
def get_status():
    with app.app_context():
        devices = Device.query.filter_by(device_type='switch').all()
        connected_devices = [device.dpid for device in devices]
        logs = EventLog.query.order_by(EventLog.timestamp.desc()).limit(100).all()
        logs_data = [{
            'timestamp': log.timestamp.isoformat(),
            'device_id':log.device_id,
            'message':log.message,
            'event_type': log.event_type,
            'data': log.data
        } for log in logs]
        asset_discoveries = AssetDiscovery.query.all()
        asset_discovery_data = [{
            'timestamp': ad.timestamp.isoformat(),
            'switch_id': ad.switch_id,
            'mac_address': ad.mac_address,
            'bytes': ad.bytes,
            'packets': ad.packets
        } for ad in asset_discoveries]
        status = 'Nodes connected' if connected_devices else 'No nodes connected'
        return jsonify({
            "connected_devices": connected_devices,
            "log": logs_data,
            "asset_discovery": asset_discovery_data,
            "status": status
        }), 200

@app.route('/install', methods=['POST'])
def install():
    if hasattr(app, 'eBPFApp'):
        # Start function installation in a separate thread if it takes time
        thread = Thread(target=install_functions, args=(app,))
        thread.start()
        return jsonify({'message': 'Function installation started.'}), 200
    else:
        return jsonify({'error': 'Controller is not running.'}), 400

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5050, debug=True)

