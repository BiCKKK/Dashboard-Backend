# controller.py
import logging
import struct
import time
from datetime import datetime, timezone
from threading import Thread
from twisted.internet import reactor

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

from shared import db
from shared.models import Device, Function, DeviceFunction, EventLog, MonitoringData, PacketCapture, AssetDiscovery, GooseAnalysisData

def extract_mac_address(packet_data):
    """
    Extracts the MAC address from the packet data.
    Adjust byte offsets based on packet structure.
    """
    return packet_data[6:12].hex()

def extract_source_ip(packet_data):
    """
    Extracts the source IP address from the packet data.
    Adjust byte offsets based on packet structure.
    """
    return f"{packet_data[26]}.{packet_data[27]}.{packet_data[28]}.{packet_data[29]}"

def extract_destination_ip(packet_data):
    """
    Extracts the destination IP address from the packet data.
    Adjust byte offsets based on packet structure.
    """
    return f"{packet_data[30]}.{packet_data[31]}.{packet_data[32]}.{packet_data[33]}"

def determine_protocol(packet_data):
    """
    Determines the protocol from the packet data.
    Adjust byte offsets based on packet structure.
    """
    protocol_number = packet_data[23]
    protocol_map = {
        6: 'TCP',
        17: 'UDP',
        1: 'ICMP'
    }
    return protocol_map.get(protocol_number, 'unknown')


class eBPFCLIApplication(eBPFCoreApplication):
    """
    Service broker for the controller that provides an abstraction between the application and data plane layers.
    """
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.connected_devices = set()
        self.connections = {}
        self.monitoring_cache = {} # To track previous bytes for bandwidth calculation

    def run(self):
        """
        Starts the Twisted reactor in a separate daemon thread.
        """
        Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}, daemon=True).start()
        logging.info("Twisted reactor started.")
        # Return self for reference if needed
        return self

    @staticmethod
    def get_switch_name(dpid, db_session):
        device = db_session.query(Device).filter_by(dpid=dpid, device_type='switch').first()
        return device.name if device else "unknown"

    @staticmethod
    def parse_values_bytes_packets(value):
        try:
            hex_value = value.hex()
            if len(hex_value) < 16:
                logging.error("Invalid value length for parsing bytes and packets.")
                return {"packets": 0, "bytes": 0}
            
            value_bytes = int.from_bytes(bytes.fromhex(hex_value[:8]), byteorder="little")
            value_packets = int.from_bytes(bytes.fromhex(hex_value[:8]), byteorder="little")
            return {"packets": value_packets, "bytes": value_bytes}
        except Exception as e:
            logging.error(f"Error parsing value bytes and packets: {e}")
            return {"packets": 0, "bytes": 0}

    @set_event_handler(Header.TABLES_LIST_REPLY)
    def tables_list_reply(self, connection, pkt):
        pass  # Implement if needed

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        if pkt.entry.table_name == "assetdisc":
            self.asset_disc_list(connection.dpid, pkt)
            return

        if pkt.entry.table_name == "monitor":
            self.monitoring_list(connection.dpid, pkt)
            return

        if pkt.entry.table_name == "goose_analyser":
            self.goose_analyser_list(connection.dpid, pkt)
            return
        
        entries = []

        if pkt.entry.table_type in [TableDefinition.HASH, TableDefinition.LPM_TRIE]:
            item_size = pkt.entry.key_size + pkt.entry.value_size
            fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

            for i in range(pkt.n_items):
                key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
                entries.append((key.hex(), value.hex()))

        elif pkt.entry.table_type == TableDefinition.ARRAY:
            item_size = pkt.entry.value_size
            fmt = "{}s".format(pkt.entry.value_size)

            for i in range(pkt.n_items):
                value = struct.unpack_from(fmt, pkt.items, i * item_size)[0]
                entries.append((i, value.hex()))

    @set_event_handler(Header.TABLE_ENTRY_GET_REPLY)
    def table_entry_get_reply(self, connection, pkt):
        pass  # Implement if needed

    def monitoring_list(self, dpid, pkt):
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        timestamp = datetime.now(timezone.utc)

        for i in range(pkt.n_items):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            valStr = self.parse_values_bytes_packets(value)
            bytes_total = int(valStr['bytes'])
            mac_address = key.hex()
            
            # Retrieve or create a monitoring record
            monitoring_record = MonitoringData.query.filter_by(
                device_id=dpid,
                mac_address=mac_address
            ).order_by(MonitoringData.timestamp.desc()).first()

            previous_bytes = monitoring_record.bandwidth if monitoring_record else 0
            bandwidth = bytes_total - previous_bytes

            if bandwidth > 0:
                new_monitoring = MonitoringData(
                    timestamp=timestamp,
                    device_id=dpid,
                    mac_address=mac_address,
                    bandwidth=bandwidth
                )
                db.session.add(new_monitoring)
                try:
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Failed to insert MonitoringData: {e}")
                    db.session.rollback()

    def goose_analyser_list(self, dpid, pkt):
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        timestamp = datetime.now(timezone.utc)

        for i in range(pkt.n_items):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            parsed_values = self.parse_values_bytes_packets(value)
            mac_address = key.hex()
            st_num = parsed_values.get('packets')
            sq_num = parsed_values.get('bytes')

            # Retrieve or create a GooseAnalysisData record
            goose_record = GooseAnalysisData.query.filter_by(
                device_id=dpid,
                mac_address=mac_address
            ).order_by(GooseAnalysisData.timestamp.desc()).first()

            if goose_record:
                goose_record.stNum = st_num,
                goose_record.sqNum = sq_num,
                goose_record.timestamp = timestamp
            else:
                new_goose = GooseAnalysisData(
                    timestamp=timestamp,
                    device_id=dpid,
                    mac_address=mac_address,
                    stNum=st_num,
                    sqNum=sq_num
                )
                db.session.add(new_goose)
            
            try:
                db.session.commit()
            except Exception as e:
                logging.error(f"Failed to insert GooseAnalysisData: {e}")
                db.session.rollback()

    def asset_disc_list(self, dpid, pkt):
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        timestamp = datetime.now(timezone.utc)

        for i in range(pkt.n_items):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            parsed_values = self.parse_values_bytes_packets(value)
            mac_address = key.hex()
            bytes_total = parsed_values.get('bytes')
            packets_count = parsed_values.get('packets')

            # Retrieve or create an AssetDiscovery record
            asset_record = AssetDiscovery.query.filter_by(
                switch_id=dpid,
                mac_address=mac_address
            ).order_by(AssetDiscovery.timestamp.desc()).first()

            if asset_record:
                asset_record.bytes = bytes_total
                asset_record.packets = packets_count
                asset_record.timestamp = timestamp
            else:
                new_asset = AssetDiscovery(
                    timestamp=timestamp, 
                    switch_id=dpid,
                    mac_address=mac_address,
                    bytes=bytes_total,
                    packets=packets_count
                )
                db.session.add(new_asset)

            try:
                db.session.commit()
            except Exception as e:
                logging.error(f"Failed to insert AssetDiscovery: {e}")
                db.session.rollback()

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        """
        Handles NOTIFY events by identifying the vendor based on packets data and requesting asset
        discovery tables from the connected device.
        """
        logging.info(f'[{connection.dpid}] Received notify event {pkt.id}, data length {len(pkt.data)}')
        logging.debug(f'Packet Data: {pkt.data.hex()}')

        vendor_map = {
            '30b216000004': 'Hitachi',
            'b4b15a000001': 'Siemens'
        }
        vendor = vendor_map.get(pkt.data.hex(), 'unknown')
        logging.info(f'IED device detected with MAC: {pkt.data.hex()} ({vendor})')

        # Log event in the database
        with self.app.app_context():
            new_event = EventLog(
                timestamp=datetime.now(timezone.utc),
                device_id=connection.dpid,
                message=f'IED device detected with MAC: {pkt.data.hex()} ({vendor})',
                event_type='INFO',
                data={'vendor': vendor}
            )
            db.session.add(new_event)
            try:
                db.session.commit()
            except Exception as e:
                logging.error(f"Failed to log event: {e}")
                db.session.rollback()

        # Request table lists
        try:
            connection.send(TableListRequest(index=0, table_name="assetdisc"))
            connection.send(TableListRequest(index=1, table_name="assetdisc"))
        except Exception as e:
            logging.error(f"Failed to send a TableListRequest: {e}")

    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        """
        Handles PACKET_IN events by logging and storing packet data.
        """
        logging.info(f"[{connection.dpid}] Received packet in {len(pkt.data)} bytes.")
        logging.debug(f"Packet Data: {pkt.data.hex()}")

        # Save packet data to the database
        with self.app.app_context():
            new_packet = PacketCapture(
                timestamp=datetime.now(timezone.utc),
                device_id=connection.dpid,
                packet_data=pkt.data,
                source_ip=extract_source_ip(pkt.data),
                destination_ip=extract_destination_ip(pkt.data),
                protocol=determine_protocol(pkt.data)
            )
            db.session.add(new_packet)

            try:
                db.session.commit()
            except Exception as e:
                logging.error(f"Failed to insert Packet data: {e}")
                db.session.rollback()

    @set_event_handler(Header.FUNCTION_LIST_REPLY)
    def function_list_reply(self, connection, pkt):
        for entry in pkt.entries:
            name = entry.name
            index = entry.index or 0
            counter = entry.counter or 0
            pass

    @set_event_handler(Header.FUNCTION_ADD_REPLY)
    def function_add_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            logging.error("Cannot add a function at this index")
        elif pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_FUNCTION:
            logging.error("Unable to install this function")
        else:
            logging.info("Function has been installed")
               
    @set_event_handler(Header.FUNCTION_REMOVE_REPLY)
    def function_remove_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            logging.error("Cannot remove a function at this index")
        else:
            logging.info("Function has been removed")

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        """
        Handles HELLO events by logging new device connections.
        """
        try:
            with self.app.app_context():
                dpid = connection.dpid
                switch_name = self.get_switch_name(dpid, db_session=db.session)
                logging.info(f"New device connected: {switch_name} (DPID: {dpid})")

                # Update or add the Device record
                device = Device.query.filter_by(dpid=dpid).first()
                if device:
                    device.status = 'connected'
                # If device is not in the topology, a new device can be added from here in case its needed
                else:
                    device = Device(
                        name=switch_name,
                        device_type='switch',
                        dpid=dpid,
                        status='connected'
                    )
                    db.session.add(device)

                # Log the connection event
                new_event = EventLog(
                    timestamp=datetime.now(timezone.utc),
                    device_id=device.id,
                    message=f"New node connected: {dpid}",
                    event_type='INFO',
                    data={}
                )
                db.session.add(new_event)
                db.session.commit()

                # Track connected devices and connections within the class
                self.connected_devices.add(dpid)
                self.connections[dpid] = connection
                logging.info(f"Device {switch_name} (DPID: {dpid}) connected and tracked.")
        except Exception as e:
            logging.error(f"Error handling HELLO event: {e}")

def start_monitoring(app, connections):
    def threaded_mon_timer():
        while True:
            with app.app_context():
                if 6 in connections:
                    connections[6].send(TableListRequest(index=0, table_name="monitor"))
                if 7 in connections:
                    connections[7].send(TableListRequest(index=0, table_name="goose_analyser"))
            logging.info("Sending monitoring request")
            time.sleep(1)

    thread = Thread(target=threaded_mon_timer)
    thread.start()

def install_functions(app):
    logging.info('Installing SGSim orchestration functions...')
    eBPFApp = app.eBPFApp
    if len(eBPFApp.connected_devices) >= 9:
        logging.info('All networking devices connected.')
        # Function install logic
        functions_to_install = [
            {"name": "forwarding", "index": "0", "path": "../functions/forwarding.o"},
            {"name": "monitor", "index": "1", "path": "../functions/monitoring.o"},
            {"name": "assetdisc", "index": "2", "path": "../functions/asset_discovery.o"},
            {"name": "goose_analyser", "index": "3", "path": "../functions/goose_analyser.o"},
            {"name": "block", "index": "4", "path": "../functions/block.o"},
            {"name": "dos_mitigation", "index": "5", "path": "../functions/dos_mitigation.o"},
            {"name": "mirroring", "index": "6", "path": "../functions/mirror.o"}
        ]
        for func in functions_to_install:
            try:
                with open(func["path"], 'rb') as f:
                    elf = f.read()
                    for dpid in eBPFApp.connections:
                        eBPFApp.connections[dpid].send(FunctionAddRequest(name="func", index=func["index"], elf=elf))
                    time.sleep(1)
                    logging.info(f"Function {func['name']} installed on all devices...")
            except Exception as e:
                logging.error(f"Error installing function {func['name']}: {e}")

        # Start monitoring after functions are installed
        start_monitoring(app, eBPFApp.connections)

        # Log event
        with app.app_context():
            event = EventLog(
                timestamp=datetime.datetime.now(),
                message="All functions installed successfully.",
                event_type='INFO'
            )
            db.session.add(event)
            db.session.commit()
    else:
        logging.error('Could not verify connected devices.')
        with app.app_context():
            event = EventLog(
                timestamp=datetime.datetime.now(),
                message="Functions installation failed.",
                event_type='ERROR'
            )
            db.session.add(event)
            db.session.commit()


