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
from sqlalchemy import text

from shared import db
from shared.models import Device, Link, EventLog

import threading
import json

# Configure logging
logging.basicConfig(level=logging.INFO)

# Global variable for the Mininet instance
net = None
network_initialized = threading.Event()

def init_socketio(sio):
    """
    Initialise the SocketIO instance
    """
    global socketio
    socketio = sio

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
                tables = ['links', 'event_logs', 'devices']
                truncate_stmt = f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE;"

                db.session.execute(text(truncate_stmt))

                db.session.commit()
                logging.info("Database has been successfully reset.")                

            net = None
            return True
        else:
            logging.warning("No active simulation to stop.")
            return False
    except Exception as e:
        logging.error(f"Error during shutdown: {e}")
        return False