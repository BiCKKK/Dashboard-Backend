# network_sim.py
import logging
import time
import subprocess
import signal
import socket
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.clean import cleanup
from mininet.cli import CLI
from eBPFSwitch import eBPFSwitch, eBPFHost
from sqlalchemy import text

from shared import db
from shared.models import Device, Link, EventLog

import threading
import json

# Configure logging
logging.basicConfig(level=logging.INFO)

# Global variable for the Mininet instance
net = None
simulation_running = False
simulation_lock = threading.Lock()

def wait_for_controller(ip, port, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try: 
            with socket.create_connection((ip, port), timeout=1):
                logging.info("Controller is available.")
                return True
        except OSError:
            logging.info("Waiting for controller to be available...")
            time.sleep(1)
    logging.error("Controller did not become available in time.")
    return False

def smartGridSimNetwork(app):
    global net, simulation_running
    logging.info("Attempting to start network simulation.")

    with simulation_lock:
        if simulation_running:
            logging.warning("Simulation is already running.")
            return
        simulation_running = True
        logging.info("Simulation running flag is set to True.")
    
    try:
        controller_ip = '127.0.0.1'
        controller_port = 5050

        if not wait_for_controller(controller_ip, controller_port):
            raise ConnectionError("Controller is not available.")

        net = Mininet(
            topo=None,
            build=False,
            ipBase='1.0.0.0/8',
            host=eBPFHost,
            switch=eBPFSwitch,
            controller=RemoteController
        )

        c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=5050)

        switchPath = "../../BPFabric/softswitch/softswitch"

        # Add switches
        DSS1GW = net.addSwitch('DSS1GW', dpid=1, switch_path=switchPath)
        DSS2GW = net.addSwitch('DSS2GW', dpid=2, switch_path=switchPath)
        WANR1 = net.addSwitch('WANR1', dpid=3, switch_path=switchPath)
        WANR2 = net.addSwitch('WANR2', dpid=4, switch_path=switchPath)
        CONTROLSW = net.addSwitch('CONTROLSW', dpid=5, switch_path=switchPath)
        DPSGW = net.addSwitch('DPSGW', dpid=6, switch_path=switchPath)
        DPSRS = net.addSwitch('DPSRS', dpid=7, switch_path=switchPath)
        DPSHV = net.addSwitch('DPSHV', dpid=8, switch_path=switchPath)
        DPSMV = net.addSwitch('DPSMV', dpid=9, switch_path=switchPath)

        # Add hosts
        DSS1RTU = net.addHost('DSS1RTU', cls=eBPFHost, ip='1.1.1.1', defaultRoute='1.1.10.10', mac='b4:b1:5a:00:00:06')
        DSS2RTU = net.addHost('DSS2RTU', cls=eBPFHost, ip='1.1.2.1', defaultRoute='1.1.10.10', mac='b4:b1:5a:00:00:07')
        CONTROL = net.addHost('CONTROL', cls=eBPFHost, ip='1.1.10.10', defaultRoute='1.1.1.1', mac='00:0c:f1:00:00:08')
        IED1 = net.addHost('IED1', cls=eBPFHost, ip='1.1.3.1', defaultRoute='1.1.10.10', mac='b4:b1:5a:00:00:01')
        IED2 = net.addHost('IED2', cls=eBPFHost, ip='1.1.3.2', defaultRoute='1.1.10.10', mac='b4:b1:5a:00:00:02')
        IED3 = net.addHost('IED3', cls=eBPFHost, ip='1.1.3.3', defaultRoute='1.1.10.10', mac='30:B2:16:00:00:03')
        IED4 = net.addHost('IED4', cls=eBPFHost, ip='1.1.3.4', defaultRoute='1.1.10.10', mac='30:B2:16:00:00:04')
        DPSHMI = net.addHost('DPSHMI', cls=eBPFHost, ip='1.1.3.10', defaultRoute='1.1.10.10', mac='00:02:b3:00:00:05')
        IDS = net.addHost('IDS', cls=eBPFHost, ip='1.1.1.8', defaultRoute='1.1.10.10', mac='00:00:0c:00:00:88')

        MBPS = {'bw':10}

        # Add links
        net.addLink(WANR2, CONTROLSW)
        net.addLink(WANR1, CONTROLSW)
        net.addLink(CONTROLSW, CONTROL)
        net.addLink(WANR1, DSS1GW, cls=TCLink , **MBPS)
        net.addLink(WANR2, DSS2GW, cls=TCLink , **MBPS)
        net.addLink(DPSGW, CONTROLSW)
        net.addLink(DPSGW, DPSRS)
        net.addLink(DPSRS, DPSHV)
        net.addLink(DPSRS, DPSMV)
        net.addLink(IED1, DPSHV)
        net.addLink(IED2, DPSHV)
        net.addLink(IED3, DPSMV)
        net.addLink(IED4, DPSMV)
        net.addLink(DPSHMI, DPSRS)
        net.addLink(DSS1GW, IDS)
        net.addLink(DSS1GW, DSS1RTU)
        net.addLink(DSS2GW, DSS2RTU)

        net.build()
        c0.start()

        # Start switches
        for switch in net.switches:
            switch.start([c0])

        logging.info("Network simulation started.")

        # Save devices and links to the database
        with app.app_context():
            # Add devices to database
            for host in net.hosts:
                device = Device.query.filter_by(name=host.name).first()
                if not device:
                    device = Device(
                        name=host.name,
                        device_type='host',
                        ip_address=host.IP(),
                        mac_address=host.MAC(),
                        status='disconnected'
                    )
                    db.session.add(device)
            for switch in net.switches:
                device = Device.query.filter_by(name=switch.name).first()
                if not device:
                    device = Device(
                        name=switch.name,
                        device_type='switch',
                        dpid=int(switch.dpid),
                        status='disconnected'
                    )
                    db.session.add(device)
            db.session.commit()

            # Add links to database
            for link in net.links:
                src = link.intf1.node
                dst = link.intf2.node
                src_device = Device.query.filter_by(name=src.name).first()
                dst_device = Device.query.filter_by(name=dst.name).first()
                if src_device and dst_device:
                    link_entry = Link(
                        source_device_id=src_device.id,
                        destination_device_id=dst_device.id,
                        link_type='ethernet',
                        attributes={}
                    )
                    db.session.add(link_entry)
            db.session.commit()
        CLI(net)

    except Exception as e:
        logging.error(f"Simulation error: {e}")
        if net:
            net.stop()
            net = None

def stop_network(app):
    global net, simulation_running
    with simulation_lock:
        if not simulation_running:
            logging.warning("No simulation running.")
            return False
        simulation_running = False

    try:
        if net:
            net.stop()
            cleanup()
            logging.info("Network simulation stopped and resources cleaned up.")

            with app.app_context():
                tables = ['links', 'event_logs', 'devices']
                truncate_stmt = f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE;"

                db.session.execute(text(truncate_stmt))

                db.session.commit()
                logging.info("Database has been successfully reset.")                

            net = None
            return True
        else:
            logging.warning("No active simulation to stop.")
            with app.app_context():
                tables = ['links', 'event_logs', 'devices']
                truncate_stmt = f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE;"

                db.session.execute(text(truncate_stmt))

                db.session.commit()
                logging.info("Database has been successfully reset.")
            return False
    except Exception as e:
        logging.error(f"Error during shutdown: {e}")
        return False
    
def sgsim_packet_count(self, line):
    "Counts received packets on every end device in the topology" 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting packet count on devices...")
    net.get('IED1').cmd('xterm -e "sudo tcpdump" &') 
    net.get('IED2').cmd('xterm -e "sudo tcpdump" &')
    net.get('IED3').cmd('xterm -e "sudo tcpdump" &')
    net.get('IED4').cmd('xterm -e "sudo tcpdump" &')
    net.get('DSS1RTU').cmd('xterm -e "sudo tcpdump" &')
    net.get('DSS2RTU').cmd('xterm -e "sudo tcpdump" &')
    net.get('CONTROL').cmd('xterm -e "sudo tcpdump" &')

def sgsim_startcom_goose():
    "Starts the GOOSE communication in the primary substation." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting GOOSE communication...")  
    net.get('DPSGW').cmd('ovs-ofctl add-flow DPSGW dl_type=0x88b8,action=DROP')     # Simulation of GOOSE multicast    
    net.get('IED1').cmd('xterm -e "cd ../comlib_dps/sgdevices/IED_GOOSE/;./ied_goose IED1-eth0" &') 
    time.sleep(0.5)
    net.get('IED4').cmd('xterm -e "cd ../comlib_dps/sgdevices/IED_GOOSE/;./ied_goose IED4-eth0" &') 
    time.sleep(0.5)
    net.get('DPSHMI').cmd('xterm -e "cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/;./dpshmi" &') 
    time.sleep(0.5)
    #net.get('DPSHMI').cmdPrint('xterm -e "cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/;./dpshmi" &') 

def sgsim_startcom_sv():
    "Starts the SV communication in the primary substation." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting SV communication...")  
    net.get('DPSGW').cmd('ovs-ofctl add-flow DPSGW dl_type=0x88ba,action=DROP')     # Simulation of SV multicast 
    net.get('IED2').cmd('xterm -e "cd ../comlib_dps/sgdevices/IED_SV/;./ied_sv IED2-eth0" &') 
    time.sleep(0.5)
    net.get('IED3').cmd('xterm -e "cd ../comlib_dps/sgdevices/IED_SV/;./ied_sv IED3-eth0" &') 
    time.sleep(0.5)
    net.get('DPSHMI').cmd('xterm -e "cd ../comlib_dps/sgdevices/DPSHMI_SV/;./dpshmi_sv 2" &') 
    time.sleep(0.5)
    net.get('DPSHMI').cmd('xterm -e "cd ../comlib_dps/sgdevices/DPSHMI_SV/;./dpshmi_sv 3" &') 
    time.sleep(0.5)

def sgsim_startcom_104(self, line):
    "Starts the IEC104 communication (periodical and read requests) for both secondary substations." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting IEC104 communication...")  
    net.get('DSS1RTU').cmd('xterm -e "cd ../comlib_dss/sgdevices/RTU/;./rtu" &') 
    time.sleep(0.5)
    net.get('DSS2RTU').cmd('xterm -e "cd ../comlib_dss/sgdevices/RTU/;./rtu" &') 
    time.sleep(0.5)
    net.get('CONTROL').cmd('xterm -e "cd ../comlib_dss/sgdevices/CONTROL/;sleep 1;./control 1.1.1.1" &') 
    time.sleep(0.5)
    net.get('CONTROL').cmd('xterm -e "cd ../comlib_dss/sgdevices/CONTROL/;sleep 1;./control 1.1.2.1" &')
      
def sgsim_attack_dos(self, line):
    "Starts the DoS attack from DSS1RTU on the control center." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting DoS attack...") 
    net.get('DSS1RTU').cmd('xterm -e "sudo hping3 -S --flood 1.1.10.10" &') 

def sgsim_startcom_sglab_goose():
    "Starts the GOOSE communication according to the SG LAB data." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting SGLAB GOOSE on devices...") 
    net.get('DPSGW').cmd('ovs-ofctl add-flow DPSGW dl_type=0x88b8,action=DROP')     # Simulation of GOOSE multicast 
    net.get('IED1').cmd('xterm -e "cd ../comlib_dps/sgdevices/IED_GOOSE/;./ied_goose_sglab IED1-eth0" &') 
    time.sleep(0.5)
    net.get('DPSHMI').cmd('xterm -e "cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/;./dpshmi" &') 

def sgsim_attack_goose_fdi():
    "Starts the False Data Injection attack on GOOSE communication." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting FDI attack...") 
    net.get('ATTACKER').cmd('xterm -e "cd ../comlib_dps/sgdevices/ATTACKER/;./fdi_goose ATTACKER-eth0" &') 
    time.sleep(0.5)
    net.get('DPSHMI').cmd('xterm -e "cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/;./dpshmi" &') 

def sgsim_startperfmon():
    "Starts the IEC104 communication (periodical and read requests) with performance monitoring." 
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting performance monitoring...")   
    net.get('DSS1RTU').cmd('xterm -e "cd ../comlib_dss/sgdevices/PERFSEND/;./perfsend" &') 
    time.sleep(0.5)  
    net.get('DSS2RTU').cmd('xterm -e "cd ../comlib_dss/sgdevices/PERFSEND/;./perfsend" &') 
    time.sleep(0.5)  
    net.get('CONTROL').cmd('xterm -e "cd ../comlib_dss/sgdevices/PERFMON/;sleep 1;./perfmon 1.1.1.1" &') 
    time.sleep(0.5)
    net.get('CONTROL').cmd('xterm -e "cd ../comlib_dss/sgdevices/PERFMON/;sleep 1;./perfmon 1.1.2.1" &')  

def sgsim_attackmirror():
    "Makes DSS ASW devices to mirror traffic to external connections. "
    if not simulation_running:
        logging.warning("Simulation is not running.") 
        return
    logging.info("Starting mirroring...")     
    net.get('DSS1ASW').cmd('ovs-ofctl add-flow DSS1ASW in_port:2,action=1,3; ovs-ofctl add-flow DSS1ASW in_port:3,action=1,2')   
    net.get('DSS2ASW').cmd('ovs-ofctl add-flow DSS2ASW in_port:2,action=1,3; ovs-ofctl add-flow DSS2ASW in_port:3,action=1,2') 