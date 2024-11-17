# controller.py
import logging
import struct
import time
import datetime
from threading import Thread
from twisted.internet import reactor

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

from shared import db
from shared.models import Device, Function, DeviceFunction, EventLog, MonitoringData, PacketCapture, AssetDiscovery, GooseAnalysisData

class eBPFCLIApplication(eBPFCoreApplication):
    """
    Service broker for the controller that provides an abstraction between the application and data plane layers.
    """
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.connected_devices = set()
        self.connections = {}

    def run(self):
        Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}).start()
        # Return self for reference if needed
        return self

    @staticmethod
    def get_switch_name(dpid):
        switch_names = {
            1: "DSS1GW",
            2: "DSS2GW",
            3: "WANR1",
            4: "WANR2",
            5: "CONTROLSW",
            6: "DPSGW",
            7: "DPSRS",
            8: "DPSHV",
            9: "DPSMV"
        }
        return switch_names.get(dpid, "unknown")

    @staticmethod
    def get_str_values(value):
        value_bytes = int.from_bytes(bytes.fromhex(value.hex()[:8]), byteorder="little")
        value_packets = int.from_bytes(bytes.fromhex(value.hex()[-8:]), byteorder="little")
        return f"{value_packets},{value_bytes}"

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

    @set_event_handler(Header.TABLE_ENTRY_GET_REPLY)
    def table_entry_get_reply(self, connection, pkt):
        pass  # Implement if needed

    def monitoring_list(self, dpid, pkt):
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        timestamp = str(datetime.datetime.now())

        for i in range(pkt.n_items):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            val_str = eBPFCLIApplication.get_str_values(value)
            bytes_total = val_str.split(",", 1)[1]

            mac_key = key.hex()
            
            # Save monitoring data to the database 
            with self.app.app_context():
                device = Device.query.filter_by(dpid=dpid).first()
                if device:
                    monitoring_data = MonitoringData(
                        timestamp=timestamp,
                        device_id=device.id,
                        mac_address=mac_key,
                        bandwidth=int(bytes_total)
                    )
                    db.session.add(monitoring_data)
                    db.session.commit()

    def goose_analyser_list(self, dpid, pkt):
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        timestamp = datetime.datetime.now()

        for i in range(pkt.n_items):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            mac_address = key.hex()
            stNum = value.hex()[:8]
            sqNum = value.hex()[-8:]

            logging.info(f"{eBPFCLIApplication.get_switch_name(dpid)}: {mac_address}, stNum: {stNum}, sqNum: {sqNum}")

            # Save GOOSE analysis data to the database
            with self.app.app_context():
                device = Device.query.filter_by(dpid=dpid).first()
                if device:
                    goose_data = GooseAnalysisData(
                        timestamp=timestamp,
                        device_id=device.id,
                        mac_address=mac_address,
                        stNum=stNum,
                        sqNum=sqNum
                    )
                    db.session.add(goose_data)
                    db.session.commit()

    def asset_disc_list(self, dpid, pkt):
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        timestamp = datetime.datetime.now()

        for i in range(pkt.n_items):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            packets, bytes_total = eBPFCLIApplication.get_str_values(value).split(',')

            with self.app.app_context():
                switch_device = Device.query.filter_by(dpid=dpid).first()
                if switch_device:
                    asset_discovery = AssetDiscovery(
                        timestamp=timestamp,
                        switch_id=switch_device.id,
                        mac_address=key.hex(),
                        bytes=int(bytes_total),
                        packets=int(packets)
                    )
                    db.session.add(asset_discovery)
                    db.session.commit()

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        vendor = ''
        mac_address = pkt.data.hex()
        if mac_address == '30b216000004':
            vendor = 'Hitachi'
        elif mac_address == 'b4b15a000001':
            vendor = 'Siemens'

        logging.info(f"[{eBPFCLIApplication.get_switch_name(connection.dpid)}] IED device detected with MAC: {mac_address} ({vendor})")

        # Log event in the database
        with self.app.app_context():
            device = Device.query.filter_by(dpid=connection.dpid).first()
            if device:
                event = EventLog(
                    timestamp=datetime.datetime.now(),
                    device_id=device.id,
                    message=f"IES device detected with MAC: {mac_address} ({vendor})",
                    event_type='INFO'
                )
                db.session.add(event)
                db.session.commit()

        # Request table lists
        connection.send(TableListRequest(index=0, table_name="assetdisc"))
        connection.send(TableListRequest(index=1, table_name="assetdisc"))

    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        logging.info(f"[{connection.dpid}] Received packet in {pkt.data.hex()}")

        # Save packet data to the database
        with self.app.app_context():
            device = Device.query.filter_by(dpid=connection.dpid).first()
            if device:
                packet_capture = PacketCapture(
                    timestamp=datetime.datetime.now(),
                    device_id=device.id,
                    packet_data=pkt.data
                )
                db.session.add(packet_capture)
                db.session.commit()

    @set_event_handler(Header.FUNCTION_LIST_REPLY)
    def function_list_reply(self, connection, pkt):
        pass  # Implement if needed

    @set_event_handler(Header.FUNCTION_ADD_REPLY)
    def function_add_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            logging.error("Cannot add a function at this index")
        elif pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_FUNCTION:
            logging.error("Unable to install this function")
        else:
            logging.info("Function has been installed")

        # Update function status in the database
        with self.app.app_context():
            device = Device.query.filter_by(dpid=connection.dpid).first()
            if device:
                function = Function.query.filter_by(name=pkt.function_name).first()
                if not function:
                    function = Function(name=pkt.function_name, description='', binary_path='', index=pkt.index)
                    db.session.add(function)
                    db.session.commit()
                device_function = DeviceFunction(
                    device_id=device.id,
                    function_id=function.id,
                    status='installed',
                    installed_at=datetime.datetime.now()
                )
                db.session.add(device_function)
                db.session.commit()
               
    @set_event_handler(Header.FUNCTION_REMOVE_REPLY)
    def function_remove_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            logging.error("Cannot remove a function at this index")
        else:
            logging.info("Function has been removed")

        # Update function status in the database
        with self.app.app_context():
            device = Device.query.filter_by(dpid=connection.dpid).first()
            if device:
                function = Function.query.filter_by(name=pkt.function_name).first()
                if function:
                    device_function = DeviceFunction.query.filter_by(device_id=device.id, function_id=function.id).first()
                    if device_function:
                        device_function.status = 'removed'
                        db.session.commit()

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        if connection.dpid not in self.connected_devices:
            self.connected_devices.add(connection.dpid)
            self.connections[connection.dpid] = connection
            logging.info(f"New device connected: {connection.dpid}")

            # Add device to the database
            with self.app.app_context():
                device = Device.query.filter_by(dpid=connection.dpid).first()
                if not device:
                    device = Device(
                        name=self.get_switch_name(connection.dpid),
                        device_type='switch',
                        dpid=connection.dpid
                    )
                    db.session.add(device)
                    db.session.commit()
                
                # Log event
                event = EventLog(
                    timestamp=datetime.datetime.now(),
                    device_id=device.id,
                    message=f"New Node connected: {connection.dpid}",
                    event_type='INFO'
                )
                db.session.add(event)
                db.session.commit()

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


