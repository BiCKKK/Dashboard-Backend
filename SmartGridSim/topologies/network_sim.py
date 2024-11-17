# network_sim.py
import logging
import time
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.clean import cleanup
from eBPFSwitch import eBPFSwitch, eBPFHost
from mininet.cli import CLI

from shared import db
from shared.models import Device, Link, EventLog

# Configure logging
logging.basicConfig(level=logging.INFO)

# Global variable for the Mininet instance
net = None

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
        net.get('DSS1GW').start([c0])
        net.get('DSS2GW').start([c0])
        net.get('WANR1').start([c0])
        net.get('WANR2').start([c0])
        net.get('CONTROLSW').start([c0])
        net.get('DPSGW').start([c0])
        net.get('DPSRS').start([c0])
        net.get('DPSHV').start([c0])
        net.get('DPSMV').start([c0])

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

    except Exception as e:
        logging.error(f"Simulation error: {e}")
        if net:
            net.stop()
            net = None

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
    
def start_goose_communication():
    global net
    if net is None:
        logging.error("Network simulation is not running.")
        return False

    try:
        net.get('DPSGW').cmd('ovs-ofctl add-flow DPSGW dl_type=0x88b8,action=DROP')
        logging.info('Inserted OpenFlow rule for GOOSE communication.')

        net.get('IED1').cmd('cd ../comlib_dps/sgdevices/IED_GOOSE/; ./ied_goose IED1-eth0 > /tmp/ied1_goose.log 2>&1 &')
        time.sleep(0.5)
        net.get('IED4').cmd('cd ../comlib_dps/sgdevices/IED_GOOSE/; ./ied_goose IED4-eth0 > /tmp/ied4_goose.log 2>&1 &')
        time.sleep(0.5)
        net.get('DPSHMI').cmd('cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/; ./dpshmi > /tmp/dpshmi_goose.log 2>&1 &')
        time.sleep(0.5)

        logging.info("GOOSE communication started.")
        return True
    except Exception as e:
        logging.error(f"Error starting GOOSE communication: {e}")
        return False

def start_sv_communication():
    global net
    if net is None:
        logging.error("Network simulation is not running.")
        return False

    try:
        net.get('DPSGW').cmd('ovs-ofctl add-flow DPSGW dl_type=0x88ba,action=DROP')
        logging.info('Inserted OpenFlow rule for SV communication.')

        net.get('IED2').cmd('cd ../comlib_dps/sgdevices/IED_SV/; ./ied_sv IED2-eth0 > /tmp/ied2_sv.log 2>&1 &')
        time.sleep(0.5)
        net.get('IED3').cmd('cd ../comlib_dps/sgdevices/IED_SV/; ./ied_sv IED3-eth0 > /tmp/ied3_sv.log 2>&1 &')
        time.sleep(0.5)
        net.get('DPSHMI').cmd('cd ../comlib_dps/sgdevices/DPSHMI_SV/; ./dpshmi_sv > /tmp/dpshmi_sv.log 2>&1 &')
        time.sleep(0.5)

        logging.info("SV communication started.")
        return True
    except Exception as e:
        logging.error(f"Error starting SV communication: {e}")
        return False

def start_iec104_communication():
    global net
    if net is None:
        logging.error("Network simulation is not running.")
        return False

    try:
        net.get('DSS1RTU').cmd('cd ../comlib_dps/sgdevices/IED_104/; ./ied104_rtu > /tmp/dss1rtu_104.log 2>&1 &')
        time.sleep(0.5)
        net.get('DSS2RTU').cmd('cd ../comlib_dps/sgdevices/IED_104/; ./ied104_rtu > /tmp/dss2rtu_104.log 2>&1 &')
        time.sleep(0.5)
        net.get('CONTROL').cmd('cd ../comlib_dps/sgdevices/CONTROL/; ./control104 > /tmp/control_104.log 2>&1 &')
        time.sleep(0.5)

        logging.info("IEC 104 communication started.")
        return True
    except Exception as e:
        logging.error(f"Error starting IEC 104 communication: {e}")
        return False

def start_goose_fdi_attack():
    global net
    if net is None:
        logging.error("Network simulation is not running.")
        return False

    try:
        net.get('ATTACKER').cmd('cd ../attacks/; ./goose_fdi_attack > /tmp/attacker_goose_fdi.log 2>&1 &')
        time.sleep(0.5)
        net.get('DPSHMI').cmd('cd ../comlib_dps/sgdevices/DPSHMI_GOOSE/; ./dpshmi > /tmp/dpshmi_goose.log 2>&1 &')
        time.sleep(0.5)

        logging.info("GOOSE FDI attack started.")
        return True
    except Exception as e:
        logging.error(f"Error starting GOOSE FDI attack: {e}")
        return False

def start_dos_attack():
    global net
    if net is None:
        logging.error("Network simulation is not running.")
        return False

    try:
        net.get('DSS1RTU').cmd('hping3 -S -p 2404 --flood 1.1.10.10 > /tmp/dos_attack.log 2>&1 &')
        logging.info("DoS attack started from DSS1RTU.")
        return True
    except Exception as e:
        logging.error(f"Error starting DoS attack: {e}")
        return False

def get_network_status():
    global net
    status = {}
    if net:
        status['running'] = True
        status['hosts'] = [host.name for host in net.hosts]
        status['switches'] = [switch.name for switch in net.switches]
    else:
        status['running'] = False
    return status

def get_log(device_name):
    log_file = f'/tmp/{device_name}.log'
    try:
        with open(log_file, 'r') as f:
            logs = f.read()
        return logs
    except FileNotFoundError:
        return None

