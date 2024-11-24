from flask import Blueprint, request, jsonify, current_app
from threading import Thread
import json
import logging

from controller import eBPFCLIApplication
from shared import db
from shared.models import Device, Link, DeviceFunction

from core.packets import *

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
                'functions': [
                    {
                        'id': func.id,
                        'function_name': func.function_name,
                        'status': func.status,
                        'index': func.index
                    } for func in device.functions
                ]
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
def install_function():
    try:
        data = request.get_json()
        logging.info(f"Received data: {data}")
        dpid = data.get('dpid')
        function_name = data.get('function_name')

        if not dpid or function_name is None:
            return jsonify({'error': 'dpid and function_name are required'}), 400
        
        app = current_app._get_current_object()
        if not hasattr(app, 'eBPFApp'):
            return jsonify({'error': 'Controller is not running'}), 400
        
        controller = app.eBPFApp

        # Get the connection to the device
        connection = controller.connections.get(int(dpid))
        if not connection:
            return jsonify({'error': f'Device {dpid} is not connected'}), 400
        device = Device.query.filter_by(dpid=int(dpid)).first()

        if not device:
            return jsonify({'error': f'Device {dpid} not found in the database.'}), 404
        
        next_index = len(device.functions)

        # Read the ELF file for the function
        elf_file_path = f'../functions/{function_name}.o'
        try:
            with open(elf_file_path, 'rb') as f:
                elf = f.read()
        except FileNotFoundError:
            return jsonify({'error': f'Function ELF file not found: {elf_file_path}'}), 404
        
        # Send the FunctionAddRequest
        function_add_request = FunctionAddRequest(name=function_name, index=next_index, elf=elf)
        connection.send(function_add_request)
        logging.info(f"Function installation request sent to device {dpid} for function {function_name}.")

        return jsonify({'message': f'Function installation initiated on device {dpid}'}), 200
    
    except Exception as e:
        logging.error(f"Error installing function: {e}")
        return jsonify({'error': 'Failed to initiate function installation'}), 500

@controller_routes.route('/remove', methods=['POST'])
def remove_function():
    try:
        data = request.get_json()
        dpid = data.get('dpid')
        function_index = data.get('function_index')  

        if not dpid or function_index is None:
            return jsonify({'error': 'device_id and function_index is required'}), 400
        
        device = Device.query.filter_by(dpid=int(dpid)).first()
        if not device:
            return jsonify({'error': f'Device {dpid} not found in teh database.'}), 404
        function = DeviceFunction.query.filter_by(device_id=device.id,index=function_index).first()
        if not function:
            return jsonify({'error': f'Function at index {function_index} not found on device {dpid}.'}), 404
        
        app = current_app._get_current_object()
        if not hasattr(app, 'eBPFApp'):
            return jsonify({'error': 'Controller is not running'}), 400
        
        controller = app.eBPFApp
        # Get the connection to the device
        connection = controller.connections.get(int(dpid))
        if not connection:
            return jsonify({'error': f'Device {dpid} is not connected'}), 400
        
        # Send the FunctionRemoveRequest
        function_remove_request = FunctionRemoveRequest(index=function_index)
        connection.send(function_remove_request)

        logging.info(f"Function removal request sent to device {dpid} at index {function_index}.")
        return jsonify({'message': f'Function removal initiated on device {dpid}'}), 200
    
    except Exception as e:
        logging.error(f"Error removing function: {e}")
        return jsonify({'error': 'Failed to initiate function removal'}), 500

