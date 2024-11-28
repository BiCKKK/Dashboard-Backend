from flask import Blueprint, request, jsonify, current_app
import logging

from controller import eBPFController, start_monitoring
from shared import db
from shared.models import Device, Link, DeviceFunction, MonitoringData, AssetDiscovery

from core.packets import *

controller_routes = Blueprint('controller_routes', __name__)

@controller_routes.route('/start', methods=['POST'])
def start():
    """
    Starts the eBPFController if its not already running.

    Returns:
        JSON response indicating the success or status of the controller.
    """
    try:
        # Get the current Flask application instance
        app = current_app._get_current_object()

        # Check if the eBPFController is already running
        if not hasattr(app, 'eBPFApp'):
            # Initiase the start the controller
            app.eBPFApp = eBPFController(app).run()
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
    """
    Stops the controller if it is currently running.

    Stop function in the controller class needs some work. Currently, it requires app to restart to start the controller again.
    """
    try:
        # Get the current Flask application instance
        app = current_app._get_current_object()

        # Check if the eBPFController is running
        if hasattr(app, 'eBPFApp'):
            # Stop the controller and clean up
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
    """
    Retrieves the total and active node counts from the database.

    Returns: 
        JSON response with total and active node counts or an an error message.
    """
    try:
        total_nodes = db.session.query(Device).count()
        active_nodes = db.session.query(Device).filter(Device.status=='connected').count()
        return jsonify({'node_count': total_nodes, 'active_node_count': active_nodes}), 200
    except Exception as e:
        logging.error(f"Error getting node counts: {e}")
        return jsonify({"error": "Failed to retrieve node counts."}), 500
    
@controller_routes.route('/topology', methods=['GET'])
def get_topology():
    """
    Retrieves the network topology including devices and links.

    Returns:
        JSON response containing serialised device and link data, or an error message.
    """
    try:
        # Fetch devices and links from the database
        devices = Device.query.all()
        links = Link.query.all()

        # Serialise devices into a structured dictionary
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
        # Serialise links into a structured dictionary
        links_data = []
        for link in links:
            links_data.append({
                'source_device_id': str(link.source_device_id),
                'destination_device_id': str(link.destination_device_id),
                'link_type': link.link_type,
            })
        
        # Return the serialised topology data as a JSON response
        return jsonify({'devices': devices_data, 'links': links_data}), 200
    except Exception as e:
        # Error handling
        logging.error(f"Error getting topology: {e}")
        return jsonify({'error': 'Failed to retrieve topology data.'}), 500


@controller_routes.route('/status', methods=['GET'])
def get_status():
    """
    Placeholder for retieving controller's current status.

    Currently unimplemented.
    """
    pass

@controller_routes.route('/install', methods=['POST'])
def install_function():
    """
    Installs a specified eBPF function on a device.

    Expects:
        JSON payload with "dpid" and "function_name" (name of the function to install).

    Returns:
        JSON response indicating the success or failure of the installation process.
    """
    try:
        # Parse request data
        data = request.get_json()
        logging.info(f"Received data: {data}")
        dpid = data.get('dpid')
        function_name = data.get('function_name')

        # Validate input
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

        # Start monitoring if the function is "monitoring"
        if function_name == 'monitoring':
            start_monitoring(app, controller.connections)
            logging.info(f"Started monitoring requests after installating function {function_name} on device {dpid}.")

        return jsonify({'message': f'Function installation initiated on device {dpid}'}), 200
    
    except Exception as e:
        logging.error(f"Error installing function: {e}")
        return jsonify({'error': 'Failed to initiate function installation'}), 500

@controller_routes.route('/remove', methods=['POST'])
def remove_function():
    """
    Removes a specified eBPF function from a device.

    Expects: 
        JSON payload with "dpid" and "function_index" (index of the function to remove).

    Returns:
        JSON response indicating the success or failure of the removal process.
    """
    try:
        # Parse request data
        data = request.get_json()
        dpid = data.get('dpid')
        function_index = data.get('function_index')  
        
        # Validate input
        if not dpid or function_index is None:
            logging.error("Missing required fields: dpid or function_index.")
            return jsonify({'error': 'device_id and function_index is required'}), 400
        
        # Find the device in the database
        device = Device.query.filter_by(dpid=int(dpid)).first()
        if not device:
            logging.error(f"Device {dpid} not found in the database.")
            return jsonify({'error': f'Device {dpid} not found in teh database.'}), 404
        
        # Find the function on the device
        function = DeviceFunction.query.filter_by(device_id=device.id,index=function_index).first()
        if not function:
            logging.error(f"Function at index {function_index} not found on device {dpid}")
            return jsonify({'error': f'Function at index {function_index} not found on device {dpid}.'}), 404
        
        # Check if the controller is running
        app = current_app._get_current_object()
        if not hasattr(app, 'eBPFApp'):
            logging.error("Controller is not running.")
            return jsonify({'error': 'Controller is not running'}), 400
        
        controller = app.eBPFApp

        # Get the connection to the device
        connection = controller.connections.get(int(dpid))
        if not connection:
            logging.error(f"Device {dpid} is not connected.")
            return jsonify({'error': f'Device {dpid} is not connected'}), 400
        
        # Send the FunctionRemoveRequest
        logging.info(f"Attempting to remove function at index {function_index} on device {dpid}")
        function_remove_request = FunctionRemoveRequest(index=function_index)
        connection.send(function_remove_request)

        logging.info(f"Function removal request sent to device {dpid} at index {function_index}.")
        return jsonify({'message': f'Function removal initiated on device {dpid}'}), 200
    
    except Exception as e:
        logging.error(f"Error removing function: {e}")
        return jsonify({'error': 'Failed to initiate function removal'}), 500

@controller_routes.route('/monitoring_data', methods=['GET'])
def get_monitoring_data():
    """
    NEEDS WORK!

    Retrieves monitoring data based on device ID and MAC address, with an optional limit.

    Query parameters (optional):
        device_id: The ID of the device for filtering.
        mac_address: MAC address for filtering.
        limit (default=100): The maximum number of records to retieve.

    Returns: 
        JSON response containing the filtered monitoring data or an error message.
    """
    try:
        # Extract query parameters
        device_id = request.args.get('device_id')
        mac_address = request.args.get('mac_address')
        limit = request.args.get('limit', 100, type=int)

        # Build the query based on filters
        query = MonitoringData.query
        if device_id:
            query = query.filter(MonitoringData.device_id == int(device_id))
        if mac_address:
            query = query.filter(MonitoringData.mac_address == mac_address)

        # Retrieve the filtered data
        monitoring_data = query.order_by(MonitoringData.timestamp.desc()).limit(limit).all()

        # Serialise results
        results = [
            {
                "timestamp": data.timestamp.isoformat(),
                "device_id": data.device_id,
                "mac_address": data.mac_address,
                "bandwidth": data.bandwidth
            }
            for data in monitoring_data
        ]

        return jsonify(results), 200
    except Exception as e:
        logging.error(f"Error fetching monitoring data: {e}")
        return jsonify({"error": "Failed to retrieve monitoring data."}), 500
    
@controller_routes.route('/asset_discovery_data', methods=['GET'])
def get_asset_discovery_data():
    """
    NEEDS IMPROVEMENTS!

    Retrieves asset discovery data based on device ID, DPID, or MAC address, with an optional limit.

    Query parameters (optional):
        device_id: The ID of the device for filtering
        dpid: The DPID for filtering (if device ID is not provided)
        mac_address: MAC address for filtering
        limit: Maximum number of records to retrieve

    Returns: 
        JSON response containing the filtered asset discovery data or an error message.
    """
    try:
        # Extract query parameters
        device_id = request.args.get('device_id', type=int)
        dpid = request.args.get('dpid', type=int)
        mac_address = request.args.get('mac_address')
        limit = request.args.get('limit', default=100, type=int)
        
        # Validate input
        if not device_id and not dpid:
            return jsonify({'error': 'Either device_id or dpid must be provided.'}), 400
        
        # Resolve device ID using DPID if not provided
        if dpid and not device_id:
            device = Device.query.filter_by(dpid=dpid).first()
            if device:
                device_id = device.id
            else:
                return jsonify({'error': f'Device with dpid {dpid} not found.'}), 404
        
        # Build query for asset discovery data
        query = AssetDiscovery.query.filter_by(switch_id=device_id)
        
        # Retrieve the filtered data
        asset_data = query.order_by(AssetDiscovery.timestamp.desc()).limit(limit).all()
        
        # Serialise results
        results = [
            {
                'timestamp': data.timestamp.isoformat(),
                'switch_id': data.switch_id,
                'mac_address': data.mac_address,
                'bytes': data.bytes,
                'packets': data.packets
            }
            for data in asset_data
        ]
        return jsonify(results), 200
    
    except Exception as e:
        logging.error(f"Error fetching asset discovery data: {e}")
        return jsonify({'error': 'Failed to retrieve asset discovery data.'}), 500