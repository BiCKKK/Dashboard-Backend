# network_sim.py
import logging
import time
import subprocess
import signal
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.clean import cleanup
from eBPFSwitch import eBPFSwitch, eBPFHost

from shared import db
from shared.models import Device, Link, EventLog

import threading
import json

# Configure logging
logging.basicConfig(level=logging.INFO)

# Global variable for the Mininet instance
net = None
# goose_processes = {}
# socketio = None
# tshark_process = None
network_initialized = threading.Event()

# def init_socketio(sio):
#     """
#     Initialise the SocketIO instance
#     """
#     global socketio
#     socketio = sio

# def install_tshark_on_hosts(hosts):
#     for host_name in hosts:
#         host = net.get(host_name)
#         logging.info(f"Installing tshark on {host_name}...")
#         install_output = host.cmd('DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y tshark')
#         if 'Setting up tshark' in install_output or 'tshark is already the newest version' in install_output:
#             logging.info(f"Successfully installed tshark on {host_name}.")
#         else:
#             logging.error(f"Failed to install tshark on {host_name}.")

def smartGridSimNetwork(app):
    global net
    try:
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
        ATTACKER = net.addHost('ATTACKER', cls=eBPFHost, ip='1.1.1.100', defaultRoute='1.1.10.10', mac='00:00:0c:00:00:99')

        MBPS = {'bw':10}

        # Add links
        net.addLink(WANR2, CONTROLSW)
        net.addLink(WANR1, CONTROLSW)
        net.addLink(CONTROL, CONTROLSW)
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
        net.addLink(DSS1GW, ATTACKER)

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
                        mac_address=host.MAC()
                    )
                    db.session.add(device)
            for switch in net.switches:
                device = Device.query.filter_by(name=switch.name).first()
                if not device:
                    device = Device(
                        name=switch.name,
                        device_type='switch',
                        dpid=int(switch.dpid)
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

        # Intall tshark on hosts
        # install_tshark_on_hosts(['IED1', 'IED4'])

        # Signal that initialization is complete
        # network_initialized.set()

    except Exception as e:
        logging.error(f"Simulation error: {e}")
        if net:
            net.stop()
            net = None
        network_initialized.set()

def stop_network(app):
    global net
    try:
        if net:
            net.stop()
            cleanup()
            logging.info("Network simulation stopped and resources cleaned up.")

            with app.app_context():
                Link.query.delete()
                db.session.commit()
                logging.info("Links removed from the database.")

                EventLog.query.delete()
                db.session.commit()
                logging.info("Device logs removed from the database.")

                Device.query.delete()
                db.session.commit()
                logging.info("Devices removed from the database.")

            net = None
            return True
        else:
            logging.warning("No active simulation to stop.")
            return False
    except Exception as e:
        logging.error(f"Error during shutdown: {e}")
        return False
    
# def start_goose_communication():
#     global net, goose_processes
#     try:
#         # Ensure network is running
#         if not net:
#             logging.error("Network simulation not running.")
#             return False
        
#         # Define hosts where GOOSE should be started 
#         goose_hosts = ['IED1', 'IED4']

#         for host_name in goose_hosts:
#             host = net.get(host_name)
#             if host_name in goose_processes:
#                 logging.warning(f"GOOSE communication already running on {host_name}.")
#                 continue
#             # Command to start the C program
#             cmd = f'cd ../comlib_dps/sgdevices/IED_GOOSE/ && ./ied_goose eth0'

#             # Start GOOSE program in the background 
#             # Using screen or nohup to keep it running
#             process_cmd = f'nohup {cmd} > /dev/null 2>&1 & echo $!'
#             pid = host.cmd(process_cmd).strip()
#             if pid:
#                 goose_processes[host_name] = pid
#                 logging.info(f"Started GOOSE communication on {host_name} with PID {pid}.")
#             else:
#                 logging.error(f"Failed to start GOOSE communicaiton on {host_name}.")
#                 return False
            
#         return True
#     except Exception as e:
#         logging.error(f"Error starting GOOSE communication: {e}")
#         return False

# def stop_goose_communication():
#     global net, goose_processes
#     try:
#         if not net:
#             logging.error("Network simulation is not running.")
#             return False
        
#         for host_name, pid in goose_processes.items():
#             host = net.get(host_name)
#             # Kill the process using PID
#             host.cmd(f'kill -SIGINT {pid}')
#             logging.info(f"Stopped GOOSE communication on host {host_name} with PID {pid}.")

#         goose_processes.clear()
#         return True
    
#     except Exception as e:
#         logging.error(f"Error stopping GOOSE communication: {e}")
#         return False
    
# def start_packet_capture():
#     global tshark_process
#     if tshark_process:
#         logging.warning("Packet capture already running.")
#         return False
    
#     try:
#         # Define hosts to capture from
#         capture_hosts = ['IED1', 'IED4']
#         tshark_process = {}
#         for host_name in capture_hosts:
#             host = net.get(host_name)
#             # Start tshark on 'eth0' within the host
#             cmd = 'tshark -i eth0 -f "ether proto 0x88b8" -T json'
#             tshark_proc = host.popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
#             def capture_packets(host, proc):
#                 for line in proc.stdout:
#                     if line.strip():
#                         try:
#                             packet_json = line.strip()
#                             if socketio:
#                                 socketio.emit('packet', packet_json)
#                                 logging.info(f"Emitted packet from {host.name}: {packet_json}")
#                         except Exception as e:
#                             logging.error(f"Error parsing packet from {host.name}: {e}")
#             # Start a thread to read tshark output
#             t = threading.Thread(target=capture_packets, args=(host, tshark_proc), daemon=True)
#             t.start()
#             tshark_process[host_name] = tshark_proc
#             logging.info(f"Started tshark on {host_name}.")
#         return True
#     except Exception as e:
#         logging.error(f"Error starting packet capture: {e}")
#         return False
    
# def stop_packet_capture():
#     global tshark_process
#     if not tshark_process:
#         logging.warning("No active packet capture to stop.")
#         return False
    
#     try:
#         for host_name, proc in tshark_process.items():
#             host = net.get(host_name)
#             host.cmd(f'kill {proc.pid}')
#             logging.info(f"Stopped tshark on {host_name}.")
#         tshark_process = {}
#         return True
#     except Exception as e:
#         logging.error(f"Error stopping packet capture: {e}")
#         return False
    
# def list_interfaces():
#     global net
#     if not net:
#         logging.error("Mininet network is not initialized.")
#         return None
#     interfaces = {}
#     for host in net.hosts:
#         host_name = host.name
#         iface_names = [iface.name for iface in host.intfList()]
#         interfaces[host_name] = iface_names
#     return interfaces

# def start_mininet():
#     # Start Mininet in a separate thread
#     mn_thread = threading.Thread(target=smartGridSimNetwork, args=(None,), daemon=True)
#     mn_thread.start()



# def start_sv_communication():
#     global net
#     if net is None:
#         logging.error("Network simulation is not running.")
#         return False

#     try:
#         net.get('DPSGW').cmd('ovs-ofctl add-flow DPSGW dl_type=0x88ba,action=DROP')
#         logging.info('Inserted OpenFlow rule for SV communication.')

#         net.get('IED2').cmd('cd ../comlib_dps/sgdevices/IED_SV/; ./ied_sv IED2-eth0 > /tmp/ied2_sv.log 2>&1 &')
#         time.sleep(0.5)
#         net.get('IED3').cmd('cd ../comlib_dps/sgdevices/IED_SV/; ./ied_sv IED3-eth0 > /tmp/ied3_sv.log 2>&1 &')
#         time.sleep(0.5)
#         net.get('DPSHMI').cmd('cd ../comlib_dps/sgdevices/DPSHMI_SV/; ./dpshmi_sv > /tmp/dpshmi_sv.log 2>&1 &')
#         time.sleep(0.5)

#         logging.info("SV communication started.")
#         return True
#     except Exception as e:
#         logging.error(f"Error starting SV communication: {e}")
#         return False

# def start_iec104_communication():
#     global net
#     if net is None:
#         logging.error("Network simulation is not running.")
#         return False

#     try:
#         net.get('DSS1RTU').cmd('cd ../comlib_dps/sgdevices/IED_104/; ./ied104_rtu > /tmp/dss1rtu_104.log 2>&1 &')
#         time.sleep(0.5)
#         net.get('DSS2RTU').cmd('cd ../comlib_dps/sgdevices/IED_104/; ./ied104_rtu > /tmp/dss2rtu_104.log 2>&1 &')
#         time.sleep(0.5)
#         net.get('CONTROL').cmd('cd ../comlib_dps/sgdevices/CONTROL/; ./control104 > /tmp/control_104.log 2>&1 &')
#         time.sleep(0.5)

#         logging.info("IEC 104 communication started.")
#         return True
#     except Exception as e:
#         logging.error(f"Error starting IEC 104 communication: {e}")
#         return False

# def start_goose_fdi_attack():
#     global net
#     if net is None:
#         logging.error("Network simulation is not running.")
#         return False

#     try:
#         net.get('ATTACKER').cmd('cd ../attacks/; ./goose_fdi_attack > /tmp/attacker_goose_fdi.log 2>&1 &')
#         time.sleep(0.5)
#         net.get('DPSHMI').cmd('cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/; ./dpshmi > /tmp/dpshmi_goose.log 2>&1 &')
#         time.sleep(0.5)

#         logging.info("GOOSE FDI attack started.")
#         return True
#     except Exception as e:
#         logging.error(f"Error starting GOOSE FDI attack: {e}")
#         return False

# def start_dos_attack():
#     global net
#     if net is None:
#         logging.error("Network simulation is not running.")
#         return False

#     try:
#         net.get('DSS1RTU').cmd('hping3 -S -p 2404 --flood 1.1.10.10 > /tmp/dos_attack.log 2>&1 &')
#         logging.info("DoS attack started from DSS1RTU.")
#         return True
#     except Exception as e:
#         logging.error(f"Error starting DoS attack: {e}")
#         return False

# def get_network_status():
#     global net
#     status = {}
#     if net:
#         status['running'] = True
#         status['hosts'] = [host.name for host in net.hosts]
#         status['switches'] = [switch.name for switch in net.switches]
#     else:
#         status['running'] = False
#     return status

# def get_log(device_name):
#     log_file = f'/tmp/{device_name}.log'
#     try:
#         with open(log_file, 'r') as f:
#             logs = f.read()
#         return logs
#     except FileNotFoundError:
#         return None

