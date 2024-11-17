# network_routes.py
from flask import Blueprint, jsonify, request, current_app
from threading import Thread
import logging

import network_sim

network_routes = Blueprint('network_routes', __name__)

@network_routes.route('/start_sim', methods=['POST'])
def start_sim():
    if network_sim.network_initialized.is_set():
        return jsonify({"status": "Simulation already started."}), 200
    sim_thread = Thread(target=network_sim.smartGridSimNetwork, args=(current_app._get_current_object(),))
    sim_thread.start()
    return jsonify({"status": "Simulation started."}), 200

@network_routes.route('/stop_sim', methods=['POST'])
def stop_sim():
    success = network_sim.stop_network(current_app._get_current_object())
    if success:
        return jsonify({"status": "Simulation stopped and resources cleaned up."}), 200
    else:
        return jsonify({"error": "Failed to stop simulation."}), 400

# @network_routes.route('/start_goose', methods=['POST'])
# def start_goose():
#     if not network_sim.network_initialized.is_set():
#         return jsonify({"error": "Network simulation is not initialized. Please start the simulation first."}), 400
#     success = network_sim.start_goose_communication()
#     if success:
#         return jsonify({"status": "GOOSE communication started."}), 200
#     else:
#         return jsonify({"error": "Failed to start GOOSE communication."}), 500
    
# @network_routes.route('/stop_goose', methods=['POST'])
# def stop_goose():
#     success = network_sim.stop_goose_communication()
#     if success:
#         return jsonify({"status": "GOOSE communication stopped."}), 200
#     else:
#         return jsonify({"error": "Failed to stop GOOSE communication."}), 500
    
# @network_routes.route('/start_capture', methods=['POST'])
# def start_capture():
#     """
#     Starts packet capturing on the specified network interface.
#     """
#     if not network_sim.network_initialized.is_set():
#         return jsonify({"error": "Network simulation is not initialized. Please start the simulation first."}), 400
    
#     success = network_sim.start_packet_capture()
#     if success: 
#         return jsonify({"status": "Packet capture started."}), 200
#     else:
#         return jsonify({"error": "Failed to start packet capture."}), 500
    
# @network_routes.route('/stop_capture', methods=['POST'])
# def stop_capture():
#     """
#     Stops the ongoing packet capture.
#     """
#     success = network_sim.stop_packet_capture()
#     if success:
#         return jsonify({"status": "Packet capture stopped."}), 200
#     else:
#         return jsonify({"error": "No active packet capture to stop."}), 400
    
# @network_routes.route('/list_interfaces', methods=['GET'])
# def list_interfaces_endpoint():
#     interfaces = network_sim.list_interfaces()
#     if interfaces:
#         return jsonify({"interfaces": interfaces}), 200
#     else:
#         return jsonify({"error": "Failed to list interfaces."}), 400

# @network_routes.route('/start_sv', methods=['POST'])
# def start_sv():
#     success = network_sim.start_sv_communication()
#     if success:
#         return jsonify({"status": "SV communication started."}), 200
#     else:
#         return jsonify({"error": "Failed to start SV communication."}), 500

# @network_routes.route('/start_iec104', methods=['POST'])
# def start_iec104():
#     success = network_sim.start_iec104_communication()
#     if success:
#         return jsonify({"status": "IEC 104 communication started."}), 200
#     else:
#         return jsonify({"error": "Failed to start IEC 104 communication."}), 500

# @network_routes.route('/start_goose_fdi_attack', methods=['POST'])
# def start_goose_fdi_attack():
#     success = network_sim.start_goose_fdi_attack()
#     if success:
#         return jsonify({"status": "GOOSE FDI attack started."}), 200
#     else:
#         return jsonify({"error": "Failed to start GOOSE FDI attack."}), 500

# @network_routes.route('/start_dos_attack', methods=['POST'])
# def start_dos_attack():
#     success = network_sim.start_dos_attack()
#     if success:
#         return jsonify({"status": "DoS attack started."}), 200
#     else:
#         return jsonify({"error": "Failed to start DoS attack."}), 500

# @network_routes.route('/status', methods=['GET'])
# def status():
#     status = network_sim.get_network_status()
#     return jsonify(status), 200

# @network_routes.route('/get_log/<device_name>', methods=['GET'])
# def get_device_log(device_name):
#     logs = network_sim.get_log(device_name)
#     if logs is not None:
#         return jsonify({"logs": logs}), 200
#     else:
#         return jsonify({"error": "Log file not found."}), 404

