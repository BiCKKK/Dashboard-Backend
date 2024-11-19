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
