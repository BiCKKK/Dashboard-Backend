# controller.py
import logging
import struct
import time
from datetime import datetime, timezone
from threading import Thread
from twisted.internet import reactor

from flask_socketio import emit

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

from shared import db
from shared.models import Device, DeviceFunction, EventLog, MonitoringData, PacketCapture, AssetDiscovery, GooseAnalysisData

class eBPFCLIApplication(eBPFCoreApplication):
    """
    Service broker for the controller that provides an abstraction between the application and data plane layers.
    """
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.connected_devices = set()
        self.connections = {}
        self.monitoring_cache = {}
        self.pending_functions ={}

    def run(self):
        """
        Starts the Twisted reactor in a separate daemon thread.
        """
        Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}, daemon=True).start()
        logging.info("Twisted reactor started.")
        # Return self for reference if needed
        return self
    
    def stop(self):
        """
        Stops the controller and twisted reactor, and performs any necessary cleanup.
        """
        logging.info("Stopping controller and Twisted reactor.")
        reactor.callFromThread(reactor.stop)

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
            value_packets = int.from_bytes(bytes.fromhex(hex_value[8:16]), byteorder="little")
            logging.debug(f"Parsed value - Bytes: {value_bytes}, Packets: {value_packets}")
            return {"bytes": value_bytes, "packets": value_packets}
        except Exception as e:
            logging.error(f"Error parsing value bytes and packets: {e}")
            return {"bytes": 0, "packets": 0}

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        try:
            if pkt.entry.table_name == "monitor":
                logging.info(f"Received monitoring data reply from device {connection.dpid}, table: {pkt.entry.table_name}.")
                self.monitoring_list(connection.dpid, pkt)
            elif pkt.entry.table_name == "assetdisc":
                logging.info(f"Received asset discovery data reply from device {connection.dpid}, table: {pkt.entry.table_name}.")
                self.asset_disc_list(connection.dpid, pkt)
        except Exception as e:
            logging.error(f"Error in TABLE_LIST_REPLY: {e}")
        
    def monitoring_list(self, dpid, pkt):
        try: 
            logging.info(f"Processing monitoring data for device {dpid}.")
            item_size = pkt.entry.key_size + pkt.entry.value_size
            fmt = f"{pkt.entry.key_size}s{pkt.entry.value_size}s"

            with self.app.app_context():
                for i in range(pkt.n_items):
                    key, value = struct.unpack_from(fmt, pkt.items, i * item_size)

                    mac_address = key.hex()
                    logging.debug(f"Processing MAC address: {mac_address}")

                    value_data = self.parse_values_bytes_packets(value)
                    bytes_total = value_data['bytes']

                    previous_bytes = self.monitoring_cache.get(mac_address, 0)
                    bandwidth = max(0, bytes_total - previous_bytes)
                    self.monitoring_cache[mac_address] = bytes_total
                    logging.debug(f"Calculated bandwidth for {mac_address}: {bandwidth} bytes/sec.")

                    monitoring_data = MonitoringData(
                        timestamp=datetime.now(timezone.utc),
                        device_id=dpid,
                        mac_address=mac_address, 
                        bandwidth=bandwidth
                    )
                    db.session.add(monitoring_data)

                db.session.commit()
                logging.info(f"Monitoring data stored for device {dpid}.")
        
        except Exception as e:
            logging.error(f"Error processing monitoring data stored for device {dpid}: {e}")
            db.session.rollback()

    def asset_disc_list(self, dpid, pkt):
        try:
            logging.info(f"Processing asset discovery data for device {dpid}.")
            item_size = pkt.entry.key_size + pkt.entry.value_size
            fmt = f"{pkt.entry.key_size}s{pkt.entry.value_size}s"

            with self.app.app_context():
                for i in range(pkt.n_items):
                    key, value = struct.unpack_from(fmt, pkt.items, i * item_size)

                    mac_address = ':'.join(f'{b:02x}' for b in key)
                    logging.debug(f"Processing MAC address: {mac_address}")

                    if len(value) != 8:
                        logging.error(f"Invalid value size: expected 8 bytes, got {len(value)} bytes.")
                        continue

                    bytes_count, packets_count = struct.unpack('<II', value)
                    logging.debug(f"Bytes: {bytes_count}, Packets: {packets_count}")

                    asset_discovery = AssetDiscovery(
                        timestamp=datetime.now(timezone.utc),
                        switch_id=dpid,
                        mac_address=mac_address,
                        bytes=bytes_count,
                        packets=packets_count
                    )
                    db.session.add(asset_discovery)
                
                db.session.commit()
                logging.info(f"Asset discovery data stored for device {dpid}")

        except Exception as e:
            logging.error(f"Error processing asset discovery data for device {dpid}: {e}")
            db.session.rollback()

    def goose_analyser_list(self, dpid, pkt):
        pass

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
        pass

    @set_event_handler(Header.FUNCTION_ADD_REPLY)
    def function_add_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            logging.error("Cannot add a function at this index")
        elif pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_FUNCTION:
            logging.error("Unable to install this function")
        else:
            logging.info("Function has been installed")
        try:
            with self.app.app_context():
                status = pkt.status
                dpid = connection.dpid
                device = Device.query.filter_by(dpid=dpid).first()
                device_id = device.id if device else None

                if status == FunctionAddReply.FunctionAddStatus.OK:
                    logging.info(f"FunctionAddReply received: name={pkt.name}, index={pkt.index}, status={pkt.index}.")
                    function_name = pkt.name or self.pending_functions.get((dpid, pkt.index))
                    if not function_name:
                        logging.error(f"Function name is missing for device {device_id} at index {pkt.index}.")
                        return

                    existing_function = DeviceFunction.query.filter_by(device_id=device_id, function_name=function_name, index=pkt.index).first()
                    if not existing_function:
                        device_function = DeviceFunction(device_id=device_id, function_name=function_name, index=pkt.index, status="installed")
                        db.session.add(device_function)
                        db.session.commit()
                        logging.info(f"Fucntion {function_name} added succesfully to device {device_id}")
                    else:
                        logging.error(f"Function addition failed on device {device_id}, status: {status}")

                    self.pending_functions.pop((dpid, pkt.index), None)
                else:
                    logging.error(f"Function addition failed for device {device_id}, status: {status}")
                
        except Exception as e:
            logging.error(f"Error handling function add reply: {e}")

    def send_function_add_request(self, connection, request):
        try:
            dpid = connection.dpid
            function_name = request.name
            index = request.index

            self.pending_functions[(dpid, index)] = function_name
            connection.send(request)
            logging.info(f"Function add request sent: name={function_name}, index={index}")
        except Exception as e:
            logging.error(f"Error sending FunctionAddRequest: {e}")
               
    @set_event_handler(Header.FUNCTION_REMOVE_REPLY)
    def function_remove_reply(self, connection, pkt):
        if pkt.status == FunctionRemoveReply.FunctionRemoveStatus.INVALID_STAGE:
            logging.error("Cannot remove a function from this index.")
        else:
            logging.info("Function has been removed successfully.")
        try: 
            with self.app.app_context():
                dpid = connection.dpid
                status = pkt.status
                index = pkt.index

                device = Device.query.filter_by(dpid=dpid).first()
                device_id = device.id if device else None

                if status == FunctionRemoveReply.FunctionRemoveStatus.OK:
                    logging.info(f"Function at index {index} removed successfully from device {device_id}.")
                    
                    if index is not None:
                        device_function = DeviceFunction.query.filter_by(device_id=device_id, index=index).first()
                        if device_function:
                            db.session.delete(device_function)
                            db.session.commit()

                        subsequent_functions = DeviceFunction.query.filter(
                            DeviceFunction.device_id == device_id,
                            DeviceFunction.index > index
                        ).order_by(DeviceFunction.index).all()

                        for func in subsequent_functions:
                            func.index -= 1
                            logging.info(f"Updated function {func.function_name} to index {func.index}.")

                        db.session.commit()
                else:
                    logging.error(f"Function removal failed on device {device_id} at index {index}, status: {status}.")

        except Exception as e:
            logging.error(f"Error handling Function_remove_reply: {e}")

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        """
        Handles HELLO events by logging new device connections.
        """
        try:
            with self.app.app_context():
                dpid = pkt.dpid
                version = pkt.version
                logging.info(f"Received HELLO from device with DPID: {dpid}, version: {version}")

                switch_name = self.get_switch_name(dpid, db_session=db.session)
                logging.info(f"New device connected: {switch_name} (DPID: {dpid})")

                if switch_name == "unknown":
                    logging.info(f"Device with DPID {dpid} is new. Default name assigned.")
                    
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
                for dpid, connection in connections.items():
                    try:
                        connection.send(TableListRequest(index=0, table_name="monitor"))
                        logging.info(f"Sent monitoring request to device {dpid}.")
                    except Exception as e:
                        logging.error(f"Error sending monitoring request to device {dpid}: {e}")
            time.sleep(30)

    thread = Thread(target=threaded_mon_timer, daemon=True)
    thread.start()
    logging.info("Started periodic monitoring requests.")
