from flask import Blueprint, jsonify, current_app
from threading import Thread
import json
import logging

from controller import eBPFCLIApplication, install_functions
from shared import db
from shared.models import Device, Link

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
    
@controller_routes.route('/stop', methods=['POST'])
def stop():
    try:
        app = current_app._get_current_object()
        if hasattr(app, 'eBPFApp'):
            app.eBPFApp.stop()
            del app.eBPFApp
            logging.info("Controller stopped.")
            return jsonify({'message': 'Controller stopped.'}), 200
        else: 
            logging.warning("Controller is not running.")
            return jsonify({'message': 'Controller is not running.'}), 200
    except Exception as e:
        logging.error(f"Failed to stop the controller: {e}")
        return jsonify({'error': 'Failed to stop the controller.'}), 500
    
@controller_routes.route('/node_counts', methods=['GET'])
def get_node_counts():
    try:
        total_nodes = db.session.query(Device).count()
        active_nodes = db.session.query(Device).filter(Device.status=='connected').count()
        return jsonify({'node_count': total_nodes, 'active_node_count': active_nodes}), 200
    except Exception as e:
        logging.error(f"Error getting node counts: {e}")
        return jsonify({"error": "Failed to retrieve node counts."}), 500
    
@controller_routes.route('/topology', methods=['GET'])
def get_topology():
    try:
        # Fetch devices and links from the database
        devices = Device.query.all()
        links = Link.query.all()
        # Serialize devices
        devices_data = []
        for device in devices:
            devices_data.append({
                'id': str(device.id),
                'name': device.name,
                'device_type': device.device_type,
                'status': device.status,
                'dpid': device.dpid,
                'ip_address': device.ip_address,
                'mac_address': device.mac_address,
            })
        # Serialize links
        links_data = []
        for link in links:
            links_data.append({
                'source_device_id': str(link.source_device_id),
                'destination_device_id': str(link.destination_device_id),
                'link_type': link.link_type,
            })
        return jsonify({'devices': devices_data, 'links': links_data}), 200
    except Exception as e:
        logging.error(f"Error getting topology: {e}")
        return jsonify({'error': 'Failed to retrieve topology data.'}), 500


@controller_routes.route('/status', methods=['GET'])
def get_status():
    pass

@controller_routes.route('/install', methods=['POST'])
def install():
    pass