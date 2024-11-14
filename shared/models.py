from . import db
from sqlalchemy.dialects.postgresql import JSON, BYTEA
from datetime import datetime

class Device(db.Model):
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    device_type = db.Column(db.String(50)) # 'host' or 'switch'
    ip_address = db.Column(db.String(15))
    mac_address = db.Column(db.String(17))
    dpid = db.Column(db.Integer) # For switches

    # Relationships
    functions = db.relationship('DeviceFunction', back_populates='device', cascade='all, delete-orphan')
    events = db.relationship('EventLog', back_populates='device', cascade='all, delete-orphan')
    monitoring_data = db.relationship('MonitoringData', back_populates='device', cascade='all, delete-orphan')
    goose_analysis_data = db.relationship('GooseAnalysisData', back_populates='device', cascade='all, delete-orphan')
    packet_captures = db.relationship('PacketCapture', back_populates='device', cascade='all, delete-orphan')
    asset_discoveries = db.relationship('AssetDiscovery', back_populates='switch', cascade='all, delete-orphan')

class Link(db.Model):
    __tablename__ = 'links'

    id = db.Column(db.Integer, primary_key=True)
    source_device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    destination_device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    link_type = db.Column(db.String(50))
    attributes = db.Column(JSON)

    source_device = db.relationship('Device', foreign_keys=[source_device_id], backref='source_links')
    destination_device = db.relationship('Device', foreign_keys=[destination_device_id], backref='destination_links')

class Function(db.Model):
    __tablename__ = 'functions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    description = db.Column(db.String(200))
    binary_path = db.Column(db.String(200))
    index = db.Column(db.Integer)

    device_functions = db.relationship('DeviceFunction', back_populates='function', cascade='all, delete-orphan')

class DeviceFunction(db.Model):
    __tablename__ = 'device_functions'

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    function_id = db.Column(db.Integer, db.ForeignKey('functions.id'))
    status = db.Column(db.String(20)) # e.g., 'installed', 'uninstalled'
    installed_at = db.Column(db.DateTime, default=datetime.now)

    device = db.relationship('Device', back_populates='functions')
    function = db.relationship('Function', back_populates='device_functions')

class EventLog(db.Model):
    __tablename__ = 'event_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True)
    message = db.Column(db.String(500))
    event_type = db.Column(db.String(20)) # 'INFO', 'ERROR', etc.
    data = db.Column(JSON)

    device = db.relationship('Device', back_populates='events')

class MonitoringData(db.Model):
    __tablename__ = 'monitoring_data'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    mac_address = db.Column(db.String(17))
    bandwidth = db.Column(db.Integer) # bytes per second

    device = db.relationship('Device', back_populates='monitoring_data')

class GooseAnalysisData(db.Model):
    __tablename__ = 'goose_analysis_data'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    mac_address = db.Column(db.String(17))
    stNum = db.Column(db.String(8))
    sqNum = db.Column(db.String(8))

    device = db.relationship('Device', back_populates='goose_analysis_data')

class PacketCapture(db.Model):
    __tablename__ = 'packet_captures'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    packet_data = db.Column(BYTEA)
    source_ip = db.Column(db.String(15))
    destination_ip = db.Column(db.String(15))
    protocol = db.Column(db.String(20))

    device = db.relationship('Device', back_populates='packet_captures')

class AssetDiscovery(db.Model):
    __tablename__ = 'asset_discovery'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    switch_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    mac_address = db.Column(db.String(17))
    bytes = db.Column(db.Integer)
    packets = db.Column(db.Integer)

    switch = db.relationship('Device', back_populates='asset_discoveries')