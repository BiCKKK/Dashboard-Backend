from . import db
from sqlalchemy.dialects.postgresql import JSON, BYTEA
from datetime import datetime
from datetime import timezone
 
# Device model for representing hosts and switches
class Device(db.Model):
	__tablename__ = 'devices'
 
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50), nullable=False) # Device name
	device_type = db.Column(db.String(50), nullable=False)  # 'host' or 'switch'
	ip_address = db.Column(db.String(15), unique=True, nullable=True) # IP address of the device
	mac_address = db.Column(db.String(17), unique=True, nullable=True) # MAC address of the device
	dpid = db.Column(db.Integer, unique=True, nullable=True)  # Data path identifier for switches
	status = db.Column(db.String(15), nullable=True) # Connection status ('connected' or 'disconnected')
 
	# Relationships to other tables
	functions = db.relationship('DeviceFunction', back_populates='device', cascade='all, delete-orphan')
	events = db.relationship('EventLog', back_populates='device', cascade='all, delete-orphan')
	monitoring_data = db.relationship('MonitoringData', back_populates='device', cascade='all, delete-orphan')
	goose_analysis_data = db.relationship('GooseAnalysisData', back_populates='device', cascade='all, delete-orphan')
	packet_captures = db.relationship('PacketCapture', back_populates='device', cascade='all, delete-orphan')
	asset_discoveries = db.relationship('AssetDiscovery', back_populates='switch', cascade='all, delete-orphan')
 
# Link model for representing connections between devices
class Link(db.Model):
	__tablename__ = 'links'
 
	id = db.Column(db.Integer, primary_key=True)
	source_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	destination_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	link_type = db.Column(db.String(50), nullable=False) # Type of link (Hardcoded to Ethernet for now)
	attributes = db.Column(JSON, nullable=True) # Additional link attributes (stays empty in the current implementation)

	# Relationships to devices
	source_device = db.relationship('Device', foreign_keys=[source_device_id], backref='source_links')
	destination_device = db.relationship('Device', foreign_keys=[destination_device_id], backref='destination_links')
 
# Functions table not implemented in this version, can be used in future versions when more function data will be needed.
# class Function(db.Model):
# 	__tablename__ = 'functions'
 
# 	id = db.Column(db.Integer, primary_key=True)
# 	name = db.Column(db.String(50), unique=True, nullable=False)
# 	description = db.Column(db.String(200), nullable=True)
# 	binary_path = db.Column(db.String(200), nullable=False)
# 	index = db.Column(db.Integer, nullable=False)
 
# 	device_functions = db.relationship('DeviceFunction', back_populates='function', cascade='all, delete-orphan')
 
# DeviceFunction model for storing functions installed on devices
class DeviceFunction(db.Model):
	__tablename__ = 'device_functions'
 
	id = db.Column(db.Integer, primary_key=True)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	function_name = db.Column(db.String(100)) # Name of the function
	status = db.Column(db.String(20)) # Status of the function 
	index = db.Column(db.Integer) # Index in the device's function table
	
	# Relationship with the Device table
	device = db.relationship('Device', back_populates='functions')

# EventLog model for recording events in the system
class EventLog(db.Model):
	__tablename__ = 'event_logs'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False) # Event time stamp
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True)
	message = db.Column(db.String(500), nullable=False) # Event message
	event_type = db.Column(db.String(20), nullable=False)  # Type of event(e.g., 'INFO', 'ERROR', etc.)
	data = db.Column(JSON, nullable=True) # Additional event data

	# Relationship to the Device model
	device = db.relationship('Device', back_populates='events')
 
# MonitoringData model for storing network monitoring information
class MonitoringData(db.Model):
	__tablename__ = 'monitoring_data'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	mac_address = db.Column(db.String(17), nullable=False) # MAC address monitored
	bandwidth = db.Column(db.Integer, nullable=False)  # Bandwidth usage in bytes per second
 
	# Relationship to the Device model
	device = db.relationship('Device', back_populates='monitoring_data')

	# Ensure unique entries for monitoring data	
	__table_args__ = (
    	db.UniqueConstraint('device_id', 'mac_address', 'timestamp', name='_monitoring_unique'),
	)
 
# GooseAnalysisData model (not implemented in this current version of the application)
class GooseAnalysisData(db.Model):
	__tablename__ = 'goose_analysis_data'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	mac_address = db.Column(db.String(17), nullable=False)
	stNum = db.Column(db.String(8), nullable=True)
	sqNum = db.Column(db.String(8), nullable=True)
 
	device = db.relationship('Device', back_populates='goose_analysis_data')
 
	__table_args__ = (
    	db.UniqueConstraint('device_id', 'mac_address', 'timestamp', name='_goose_analysis_unique'),
	)
 
# PacketCapture model (not implemented in this current version of the application)
class PacketCapture(db.Model):
	__tablename__ = 'packet_captures'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	packet_data = db.Column(BYTEA, nullable=False)
	source_ip = db.Column(db.String(15), nullable=False)
	destination_ip = db.Column(db.String(15), nullable=False)
	protocol = db.Column(db.String(20), nullable=False)
 
	device = db.relationship('Device', back_populates='packet_captures')
 
# AssetDiscovery model for storing discovered assets
class AssetDiscovery(db.Model):
	__tablename__ = 'asset_discovery'
 
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
	switch_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	mac_address = db.Column(db.String(17), nullable=False)
	bytes = db.Column(db.Integer, nullable=False)
	packets = db.Column(db.Integer, nullable=False)

	# Relationship to the Device model
	switch = db.relationship('Device', back_populates='asset_discoveries')
 
	# Ensure unique entries for asset discovery data
	__table_args__ = (
    	db.UniqueConstraint('switch_id', 'mac_address', 'timestamp', name='_asset_discovery_unique'),
	)

