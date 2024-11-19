from . import db
from sqlalchemy.dialects.postgresql import JSON, BYTEA
from datetime import datetime
 
 
class Device(db.Model):
	__tablename__ = 'devices'
 
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50), nullable=False)
	device_type = db.Column(db.String(50), nullable=False)  # 'host' or 'switch'
	ip_address = db.Column(db.String(15), unique=True, nullable=True)
	mac_address = db.Column(db.String(17), unique=True, nullable=True)
	dpid = db.Column(db.Integer, unique=True, nullable=True)  # For switches
	status = db.Column(db.String(15), nullable=True)
 
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
	source_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	destination_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	link_type = db.Column(db.String(50), nullable=False)
	attributes = db.Column(JSON, nullable=True)
 
	source_device = db.relationship('Device', foreign_keys=[source_device_id], backref='source_links')
	destination_device = db.relationship('Device', foreign_keys=[destination_device_id], backref='destination_links')
 
 
class Function(db.Model):
	__tablename__ = 'functions'
 
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50), unique=True, nullable=False)
	description = db.Column(db.String(200), nullable=True)
	binary_path = db.Column(db.String(200), nullable=False)
	index = db.Column(db.Integer, nullable=False)
 
	device_functions = db.relationship('DeviceFunction', back_populates='function', cascade='all, delete-orphan')
 
 
class DeviceFunction(db.Model):
	__tablename__ = 'device_functions'
 
	id = db.Column(db.Integer, primary_key=True)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	function_id = db.Column(db.Integer, db.ForeignKey('functions.id', ondelete='CASCADE'), nullable=False)
	status = db.Column(db.String(20), nullable=False)  # e.g., 'installed', 'uninstalled'
	installed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
 
	device = db.relationship('Device', back_populates='functions')
	function = db.relationship('Function', back_populates='device_functions')
 
 
class EventLog(db.Model):
	__tablename__ = 'event_logs'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True)
	message = db.Column(db.String(500), nullable=False)
	event_type = db.Column(db.String(20), nullable=False)  # 'INFO', 'ERROR', etc.
	data = db.Column(JSON, nullable=True)
 
	device = db.relationship('Device', back_populates='events')
 
 
class MonitoringData(db.Model):
	__tablename__ = 'monitoring_data'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	mac_address = db.Column(db.String(17), nullable=False)
	bandwidth = db.Column(db.Integer, nullable=False)  # bytes per second
 
	device = db.relationship('Device', back_populates='monitoring_data')
 
	__table_args__ = (
    	db.UniqueConstraint('device_id', 'mac_address', 'timestamp', name='_monitoring_unique'),
	)
 
 
class GooseAnalysisData(db.Model):
	__tablename__ = 'goose_analysis_data'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	mac_address = db.Column(db.String(17), nullable=False)
	stNum = db.Column(db.String(8), nullable=True)
	sqNum = db.Column(db.String(8), nullable=True)
 
	device = db.relationship('Device', back_populates='goose_analysis_data')
 
	__table_args__ = (
    	db.UniqueConstraint('device_id', 'mac_address', 'timestamp', name='_goose_analysis_unique'),
	)
 
 
class PacketCapture(db.Model):
	__tablename__ = 'packet_captures'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	packet_data = db.Column(BYTEA, nullable=False)
	source_ip = db.Column(db.String(15), nullable=False)
	destination_ip = db.Column(db.String(15), nullable=False)
	protocol = db.Column(db.String(20), nullable=False)
 
	device = db.relationship('Device', back_populates='packet_captures')
 
 
class AssetDiscovery(db.Model):
	__tablename__ = 'asset_discovery'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	switch_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	mac_address = db.Column(db.String(17), nullable=False)
	bytes = db.Column(db.Integer, nullable=False)
	packets = db.Column(db.Integer, nullable=False)
 
	switch = db.relationship('Device', back_populates='asset_discoveries')
 
	__table_args__ = (
    	db.UniqueConstraint('switch_id', 'mac_address', 'timestamp', name='_asset_discovery_unique'),
	)

