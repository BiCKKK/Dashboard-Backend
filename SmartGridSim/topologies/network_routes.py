# network_routes.py
from flask import Blueprint, jsonify, request, current_app
from threading import Thread
import logging

import network_sim

network_routes = Blueprint('network_routes', __name__)

@network_routes.route('/start_sim', methods=['POST'])
def start_sim():
    with network_sim.simulation_lock:
        if network_sim.simulation_running:
            logging.info("Simulation already running start_sim ignored.")
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

@network_routes.route('/packet_count', methods=['POST'])
def packet_count():
    network_sim.sgsim_packet_count()
    return jsonify({'status': 'Packet count started.'}), 200

@network_routes.route('/start_goose', methods=['POST'])
def start_goose():
    network_sim.sgsim_startcom_goose()
    return jsonify({'status': 'Goose communication started.'}), 200

@network_routes.route('/start_sv', methods=['POST'])
def start_sv():
    network_sim.sgsim_startcom_sv()
    return jsonify({'status': 'SV communication started.'}), 200

@network_routes.route('/start_iec104', methods=['POST'])
def start_iec104():
    network_sim.sgsim_startcom_104()
    return jsonify({'status': 'IEC104 communication started.'}), 200

@network_routes.route('/dos_attack', methods=['POST'])
def dos_attack():
    network_sim.sgsim_attack_dos()
    return jsonify({'status': 'DoS attack started.'}), 200

@network_routes.route('sglab_goose', methods=['POST'])
def sglab_goose():
    network_sim.sgsim_startcom_sglab_goose()
    return jsonify({'status': 'SGLab Goose communication started.'}), 200

@network_routes.route('/fdi_attack', methods=['POST'])
def fdi_attack():
    network_sim.sgsim_attack_goose_fdi()
    return jsonify({'status': 'FDI attack started.'}), 200

@network_routes.route('/perfmon', methods=['POST'])
def perfmon():
    network_sim.sgsim_startperfmon()
    return jsonify({'status': 'IEC104 communication (periodical and read requests) with performance monitoring started.'}), 200

@network_routes.route('/mirror_attack', methods=['POST'])
def mirror_attack():
    network_sim.sgsim_attackmirror()
    return jsonify({'status': 'Mirroring started.'}), 200