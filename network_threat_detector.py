#!/usr/bin/env python3
"""
Advanced Network Traffic Analysis and Threat Detection System
MIT-grade professional cybersecurity tool for real-time network monitoring
and intelligent threat detection using machine learning algorithms.

Author: Professional Security Analyst
Version: 1.0.0
"""

import os
import sys
import time
import json
import threading
import logging
import sqlite3
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Set
import socket
import struct
import hashlib
import base64
import signal
import queue

# Third-party imports
import scapy.all as scapy
import numpy as np
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, render_template, jsonify, request
import plotly.graph_objs as go
import plotly.utils

# Configuration
@dataclass
class ThreatConfig:
    """Threat detection configuration parameters"""
    scan_threshold: int = 50  # Port scan threshold
    ddos_threshold: int = 1000  # DDoS threshold
    anomaly_contamination: float = 0.1  # ML anomaly contamination
    window_size: int = 300  # Time window in seconds
    max_connections: int = 100  # Max connections per IP
    suspicious_ports: Set[int] = None
    whitelist_ips: Set[str] = None
    
    def __post_init__(self):
        if self.suspicious_ports is None:
            self.suspicious_ports = set(range(1, 65536))  # ALL PORTS - Monitor everything
        if self.whitelist_ips is None:
            self.whitelist_ips = {'127.0.0.1', '::1'}

@dataclass
class NetworkPacket:
    """Network packet data structure"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    payload_size: int
    flags: str
    ttl: int
    packet_hash: str
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ThreatEvent:
    """Threat event data structure"""
    event_id: str
    timestamp: datetime
    threat_type: str
    severity: str
    src_ip: str
    dst_ip: str
    description: str
    raw_data: Dict
    confidence: float
    mitigated: bool = False
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

class DatabaseManager:
    """SQLite database manager for storing network data and threats"""
    
    def __init__(self, db_path: str = "network_threats.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                payload_size INTEGER,
                flags TEXT,
                ttl INTEGER,
                packet_hash TEXT
            )
        ''')
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                timestamp TEXT,
                threat_type TEXT,
                severity TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                description TEXT,
                raw_data TEXT,
                confidence REAL,
                mitigated BOOLEAN DEFAULT 0
            )
        ''')
        
        # Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_packets INTEGER,
                unique_ips INTEGER,
                threats_detected INTEGER,
                protocols TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_packet(self, packet: NetworkPacket):
        """Store packet in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port,
                               protocol, packet_size, payload_size, flags, ttl, packet_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (packet.timestamp, packet.src_ip, packet.dst_ip, packet.src_port,
              packet.dst_port, packet.protocol, packet.packet_size, packet.payload_size,
              packet.flags, packet.ttl, packet.packet_hash))
        conn.commit()
        conn.close()
    
    def store_threat(self, threat: ThreatEvent):
        """Store threat event in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threats 
            (event_id, timestamp, threat_type, severity, src_ip, dst_ip,
             description, raw_data, confidence, mitigated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (threat.event_id, threat.timestamp.isoformat(), threat.threat_type,
              threat.severity, threat.src_ip, threat.dst_ip, threat.description,
              json.dumps(threat.raw_data), threat.confidence, threat.mitigated))
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, hours: int = 24) -> List[Dict]:
        """Get recent threats from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        cursor.execute('''
            SELECT * FROM threats WHERE timestamp > ? ORDER BY timestamp DESC
        ''', (since,))
        threats = []
        for row in cursor.fetchall():
            threats.append({
                'id': row[0], 'event_id': row[1], 'timestamp': row[2],
                'threat_type': row[3], 'severity': row[4], 'src_ip': row[5],
                'dst_ip': row[6], 'description': row[7], 'raw_data': row[8],
                'confidence': row[9], 'mitigated': row[10]
            })
        conn.close()
        return threats

class PacketCapture:
    """Advanced packet capture and analysis engine"""
    
    def __init__(self, config: ThreatConfig, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.packet_queue = queue.Queue()
        self.capture_thread = None
        self.running = False
        self.interface = None
        self.packets_captured = 0
        self.start_time = time.time()
        
        # Network statistics
        self.ip_stats = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'ports': set(), 'first_seen': time.time()
        })
        self.port_scan_tracker = defaultdict(lambda: defaultdict(int))
        self.connection_tracker = defaultdict(set)
        
    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        try:
            interfaces = scapy.get_if_list()
            return [iface for iface in interfaces if not iface.startswith('lo')]
        except Exception as e:
            logging.error(f"Error getting interfaces: {e}")
            return []
    
    def packet_hash(self, packet) -> str:
        """Generate unique hash for packet deduplication"""
        hash_input = f"{packet.time}{len(packet)}"
        return hashlib.md5(hash_input.encode()).hexdigest()
    
    def extract_packet_info(self, packet) -> Optional[NetworkPacket]:
        """Extract detailed information from packet"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ttl = packet[IP].ttl
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                ttl = packet[IPv6].hlim
            else:
                return None
            
            protocol = "OTHER"
            src_port = dst_port = 0
            flags = ""
            payload_size = 0
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
                payload_size = len(packet[TCP].payload)
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload_size = len(packet[UDP].payload)
            elif ICMP in packet:
                protocol = "ICMP"
                payload_size = len(packet[ICMP].payload)
            
            packet_size = len(packet)
            packet_hash = self.packet_hash(packet)
            
            return NetworkPacket(
                timestamp=packet.time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                payload_size=payload_size,
                flags=flags,
                ttl=ttl,
                packet_hash=packet_hash
            )
        except Exception as e:
            logging.error(f"Error extracting packet info: {e}")
            return None
    
    def update_statistics(self, packet: NetworkPacket):
        """Update network statistics"""
        # Update IP statistics
        self.ip_stats[packet.src_ip]['packets'] += 1
        self.ip_stats[packet.src_ip]['bytes'] += packet.packet_size
        self.ip_stats[packet.src_ip]['ports'].add(packet.dst_port)
        
        # Track port scans
        if packet.protocol == "TCP":
            self.port_scan_tracker[packet.src_ip][packet.dst_port] += 1
        
        # Track connections
        connection_key = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}"
        self.connection_tracker[packet.src_ip].add(connection_key)
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        if not self.running:
            return
        
        packet_info = self.extract_packet_info(packet)
        if packet_info:
            self.packet_queue.put(packet_info)
            self.packets_captured += 1
            self.update_statistics(packet_info)
            self.db_manager.store_packet(packet_info)
    
    def start_capture(self, interface: str = None):
        """Start packet capture"""
        if interface is None:
            interfaces = self.get_network_interfaces()
            if not interfaces:
                raise Exception("No network interfaces available")
            interface = interfaces[0]
        
        self.interface = interface
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        logging.info(f"Started packet capture on interface: {interface}")
    
    def _capture_loop(self):
        """Main capture loop"""
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_handler, 
                       store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            logging.error(f"Capture error: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logging.info("Stopped packet capture")

class ThreatDetectionEngine:
    """Advanced threat detection using multiple algorithms"""
    
    def __init__(self, config: ThreatConfig, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.threat_events = []
        self.ml_models = {}
        self.scalers = {}
        self.init_ml_models()
        
        # Detection thresholds
        self.port_scan_thresholds = defaultdict(int)
        self.ddos_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.anomaly_buffer = deque(maxlen=10000)
        
    def init_ml_models(self):
        """Initialize machine learning models"""
        # Isolation Forest for anomaly detection
        self.ml_models['isolation'] = IsolationForest(
            contamination=self.config.anomaly_contamination,
            random_state=42,
            n_estimators=100
        )
        
        # DBSCAN for clustering
        self.ml_models['dbscan'] = DBSCAN(eps=0.5, min_samples=5)
        
        # Scaler for data normalization
        self.scalers['standard'] = StandardScaler()
    
    def detect_port_scan(self, packet: NetworkPacket) -> Optional[ThreatEvent]:
        """Detect port scanning attacks"""
        if packet.src_ip in self.config.whitelist_ips:
            return None
        
        src_ip = packet.src_ip
        unique_ports = len(self.port_scan_tracker.get(src_ip, {}))
        
        if unique_ports > self.config.scan_threshold:
            event_id = f"PORT_SCAN_{int(time.time())}_{src_ip}"
            threat = ThreatEvent(
                event_id=event_id,
                timestamp=datetime.fromtimestamp(packet.timestamp),
                threat_type="PORT_SCAN",
                severity="HIGH",
                src_ip=src_ip,
                dst_ip="MULTIPLE",
                description=f"Port scan detected from {src_ip}. Scanned {unique_ports} ports.",
                raw_data={'scanned_ports': list(self.port_scan_tracker[src_ip].keys())},
                confidence=min(1.0, unique_ports / self.config.scan_threshold)
            )
            return threat
        return None
    
    def detect_ddos(self, packet: NetworkPacket) -> Optional[ThreatEvent]:
        """Detect DDoS attacks"""
        if packet.src_ip in self.config.whitelist_ips:
            return None
        
        src_ip = packet.src_ip
        current_time = packet.timestamp
        self.ddos_tracker[src_ip].append(current_time)
        
        # Count packets in time window
        recent_packets = sum(1 for t in self.ddos_tracker[src_ip] 
                           if current_time - t <= self.config.window_size)
        
        if recent_packets > self.config.ddos_threshold:
            event_id = f"DDOS_{int(time.time())}_{src_ip}"
            threat = ThreatEvent(
                event_id=event_id,
                timestamp=datetime.fromtimestamp(current_time),
                threat_type="DDOS",
                severity="CRITICAL",
                src_ip=src_ip,
                dst_ip=packet.dst_ip,
                description=f"DDoS attack detected from {src_ip}. {recent_packets} packets in {self.config.window_size}s.",
                raw_data={'packet_count': recent_packets, 'time_window': self.config.window_size},
                confidence=min(1.0, recent_packets / self.config.ddos_threshold)
            )
            return threat
        return None
    
    def detect_anomalies(self, packets: List[NetworkPacket]) -> List[ThreatEvent]:
        """Detect anomalies using machine learning"""
        if len(packets) < 100:
            return []
        
        # Prepare features
        features = []
        for packet in packets:
            feature_vector = [
                packet.packet_size,
                packet.payload_size,
                packet.ttl,
                len(packet.flags) if packet.flags else 0,
                hash(packet.src_ip) % 1000,
                hash(packet.dst_ip) % 1000,
                hash(packet.protocol) % 10
            ]
            features.append(feature_vector)
        
        features = np.array(features)
        
        # Normalize features
        try:
            features_scaled = self.scalers['standard'].fit_transform(features)
            
            # Predict anomalies
            anomalies = self.ml_models['isolation'].fit_predict(features_scaled)
            
            threats = []
            for i, (packet, anomaly_score) in enumerate(zip(packets, anomalies)):
                if anomaly_score == -1:  # Anomaly detected
                    event_id = f"ANOMALY_{int(time.time())}_{i}"
                    threat = ThreatEvent(
                        event_id=event_id,
                        timestamp=datetime.fromtimestamp(packet.timestamp),
                        threat_type="ANOMALY",
                        severity="MEDIUM",
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        description=f"Anomalous traffic detected from {packet.src_ip} to {packet.dst_ip}",
                        raw_data={'features': features[i].tolist(), 'anomaly_score': float(anomaly_score)},
                        confidence=0.7
                    )
                    threats.append(threat)
            
            return threats
        except Exception as e:
            logging.error(f"Error in anomaly detection: {e}")
            return []
    
    def detect_suspicious_ports(self, packet: NetworkPacket) -> Optional[ThreatEvent]:
        """Detect access to suspicious ports"""
        if packet.dst_port in self.config.suspicious_ports:
            event_id = f"SUSPICIOUS_PORT_{int(time.time())}_{packet.src_ip}"
            threat = ThreatEvent(
                event_id=event_id,
                timestamp=datetime.fromtimestamp(packet.timestamp),
                threat_type="SUSPICIOUS_PORT_ACCESS",
                severity="MEDIUM",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"Access to suspicious port {packet.dst_port} ({packet.protocol})",
                raw_data={'port': packet.dst_port, 'protocol': packet.protocol},
                confidence=0.6
            )
            return threat
        return None
    
    def analyze_packets(self, packets: List[NetworkPacket]) -> List[ThreatEvent]:
        """Analyze packets for threats"""
        threats = []
        
        for packet in packets:
            # Port scan detection
            port_scan_threat = self.detect_port_scan(packet)
            if port_scan_threat:
                threats.append(port_scan_threat)
            
            # DDoS detection
            ddos_threat = self.detect_ddos(packet)
            if ddos_threat:
                threats.append(ddos_threat)
            
            # Suspicious port detection
            suspicious_threat = self.detect_suspicious_ports(packet)
            if suspicious_threat:
                threats.append(suspicious_threat)
        
        # ML-based anomaly detection
        anomaly_threats = self.detect_anomalies(packets)
        threats.extend(anomaly_threats)
        
        # Store threats
        for threat in threats:
            self.db_manager.store_threat(threat)
            self.threat_events.append(threat)
        
        return threats

class WebDashboard:
    """Real-time web dashboard for threat monitoring"""
    
    def __init__(self, db_manager: DatabaseManager, detection_engine: ThreatDetectionEngine):
        self.app = Flask(__name__)
        self.db_manager = db_manager
        self.detection_engine = detection_engine
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return self.generate_dashboard_html()
        
        @self.app.route('/api/threats')
        def get_threats():
            """Get recent threats API"""
            hours = request.args.get('hours', 24, type=int)
            threats = self.db_manager.get_recent_threats(hours)
            return jsonify(threats)
        
        @self.app.route('/api/statistics')
        def get_statistics():
            """Get network statistics API"""
            stats = self.get_network_statistics()
            return jsonify(stats)
        
        @self.app.route('/api/stop')
        def stop_monitoring():
            """Stop monitoring API"""
            return jsonify({'status': 'stopped'})
        
        @self.app.route('/api/packets')
        def get_recent_packets():
            """Get recent packets API - Wireshark style - Unlimited"""
            limit = request.args.get('limit', 10000, type=int)  # Default 10k packets
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
                       packet_size, payload_size, flags, ttl, packet_hash
                FROM packets 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            packets = []
            for row in cursor.fetchall():
                packets.append({
                    'timestamp': row[0],
                    'time_formatted': datetime.fromtimestamp(row[0]).strftime('%H:%M:%S.%f')[:-3],
                    'src_ip': row[1],
                    'dst_ip': row[2],
                    'src_port': row[3],
                    'dst_port': row[4],
                    'protocol': row[5],
                    'packet_size': row[6],
                    'payload_size': row[7],
                    'flags': row[8],
                    'ttl': row[9],
                    'packet_hash': row[10]
                })
            
            conn.close()
            return jsonify(packets)
    
    def get_network_statistics(self) -> Dict:
        """Get current network statistics"""
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        # Total packets
        cursor.execute('SELECT COUNT(*) FROM packets')
        total_packets = cursor.fetchone()[0]
        
        # Unique IPs
        cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM packets')
        unique_ips = cursor.fetchone()[0]
        
        # Recent threats
        cursor.execute('SELECT COUNT(*) FROM threats WHERE timestamp > datetime("now", "-1 hour")')
        recent_threats = cursor.fetchone()[0]
        
        # Protocol distribution
        cursor.execute('SELECT protocol, COUNT(*) FROM packets GROUP BY protocol')
        protocols = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_packets': total_packets,
            'unique_ips': unique_ips,
            'recent_threats': recent_threats,
            'protocols': protocols
        }
    
    def generate_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Network Threat Detection Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 5px; flex: 1; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .threats { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .threat { padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; background: #fdf2f2; }
        .threat.high { border-left-color: #e74c3c; }
        .threat.medium { border-left-color: #f39c12; }
        .threat.low { border-left-color: #27ae60; }
        .charts { display: flex; gap: 20px; margin: 20px 0; }
        .chart { background: white; padding: 20px; border-radius: 5px; flex: 1; }
        
        /* Packet capture styles */
        .packets { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .packet-controls { margin-bottom: 15px; }
        .packet-controls button { margin-right: 10px; padding: 5px 10px; background: #3498db; color: white; border: none; border-radius: 3px; cursor: pointer; }
        .packet-controls button:hover { background: #2980b9; }
        .packet-controls input { padding: 5px; border: 1px solid #ddd; border-radius: 3px; width: 100px; }
        .packet-table-container { max-height: 400px; overflow-y: auto; border: 1px solid #ddd; }
        .packet-table { width: 100%; border-collapse: collapse; font-family: 'Courier New', monospace; font-size: 12px; }
        .packet-table th { background: #34495e; color: white; padding: 8px; text-align: left; position: sticky; top: 0; }
        .packet-table td { padding: 6px 8px; border-bottom: 1px solid #ecf0f1; }
        .packet-table tr:hover { background: #f8f9fa; }
        .packet-table tr.tcp { color: #2c3e50; }
        .packet-table tr.udp { color: #27ae60; }
        .packet-table tr.icmp { color: #e74c3c; }
        .packet-table tr.other { color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Threat Detection System</h1>
        <p>Real-time monitoring and analysis</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3 id="total-packets">0</h3>
            <p>Total Packets</p>
        </div>
        <div class="stat-card">
            <h3 id="unique-ips">0</h3>
            <p>Unique IPs</p>
        </div>
        <div class="stat-card">
            <h3 id="recent-threats">0</h3>
            <p>Recent Threats</p>
        </div>
    </div>
    
    <div class="charts">
        <div class="chart">
            <div id="protocol-chart"></div>
        </div>
        <div class="chart">
            <div id="threat-timeline"></div>
        </div>
    </div>
    
    <div class="packets">
        <h2>Live Packet Capture (Wireshark Style)</h2>
        <div class="packet-controls">
            <button onclick="toggleAutoScroll()">Auto Scroll: <span id="scroll-status">ON</span></button>
            <button onclick="clearPackets()">Clear</button>
            <input type="number" id="packet-limit" value="10000" min="100" max="100000" placeholder="Packet limit">
        </div>
        <div class="packet-table-container">
            <table class="packet-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Length</th>
                        <th>Info</th>
                    </tr>
                </thead>
                <tbody id="packet-list">
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="threats">
        <h2>Recent Threats</h2>
        <div id="threat-list"></div>
    </div>
    
    <script>
        let autoScroll = true;
        let packetLimit = 50;
        let lastPacketCount = 0;
        
        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            document.getElementById('scroll-status').textContent = autoScroll ? 'ON' : 'OFF';
        }
        
        function clearPackets() {
            document.getElementById('packet-list').innerHTML = '';
        }
        
        function updatePackets() {
            const limit = document.getElementById('packet-limit').value || 10000;
            
            fetch(`/api/packets?limit=${limit}`)
                .then(response => response.json())
                .then(packets => {
                    const packetList = document.getElementById('packet-list');
                    
                    // Only update if we have new packets
                    if (packets.length !== lastPacketCount) {
                        packetList.innerHTML = '';
                        
                        packets.forEach(packet => {
                            const row = document.createElement('tr');
                            row.className = packet.protocol.toLowerCase();
                            
                            const srcPort = packet.src_port > 0 ? `:${packet.src_port}` : '';
                            const dstPort = packet.dst_port > 0 ? `:${packet.dst_port}` : '';
                            const src = `${packet.src_ip}${srcPort}`;
                            const dst = `${packet.dst_ip}${dstPort}`;
                            
                            let info = '';
                            if (packet.flags) {
                                info += `Flags: ${packet.flags} `;
                            }
                            if (packet.ttl) {
                                info += `TTL: ${packet.ttl} `;
                            }
                            if (packet.payload_size > 0) {
                                info += `Payload: ${packet.payload_size}B`;
                            }
                            
                            row.innerHTML = `
                                <td>${packet.time_formatted}</td>
                                <td>${src}</td>
                                <td>${dst}</td>
                                <td>${packet.protocol}</td>
                                <td>${packet.packet_size}</td>
                                <td>${info}</td>
                            `;
                            
                            packetList.appendChild(row);
                        });
                        
                        lastPacketCount = packets.length;
                        
                        // Auto scroll to bottom if enabled
                        if (autoScroll) {
                            const container = document.querySelector('.packet-table-container');
                            container.scrollTop = container.scrollHeight;
                        }
                    }
                });
        }
        
        function updateData() {
            fetch('/api/statistics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();
                    document.getElementById('unique-ips').textContent = data.unique_ips.toLocaleString();
                    document.getElementById('recent-threats').textContent = data.recent_threats.toLocaleString();
                    
                    // Protocol chart
                    const protocolData = [{
                        values: Object.values(data.protocols),
                        labels: Object.keys(data.protocols),
                        type: 'pie'
                    }];
                    Plotly.newPlot('protocol-chart', protocolData, {title: 'Protocol Distribution'});
                });
            
            fetch('/api/threats')
                .then(response => response.json())
                .then(threats => {
                    const threatList = document.getElementById('threat-list');
                    threatList.innerHTML = '';
                    
                    threats.slice(0, 10).forEach(threat => {
                        const div = document.createElement('div');
                        div.className = `threat ${threat.severity.toLowerCase()}`;
                        div.innerHTML = `
                            <strong>${threat.threat_type}</strong> - ${threat.timestamp}<br>
                            ${threat.description}<br>
                            <small>Source: ${threat.src_ip} | Confidence: ${(threat.confidence * 100).toFixed(1)}%</small>
                        `;
                        threatList.appendChild(div);
                    });
                });
            
            // Update packets
            updatePackets();
        }
        
        // Initial load
        updateData();
        
        // Update every 500ms for ultra real-time packet capture
        setInterval(updateData, 500);
    </script>
</body>
</html>
        '''
    
    def run(self, host='127.0.0.1', port=8080, debug=False):
        """Run the web dashboard"""
        self.app.run(host=host, port=port, debug=debug)

class NetworkThreatDetector:
    """Main application class"""
    
    def __init__(self, config: ThreatConfig = None):
        self.config = config or ThreatConfig()
        self.db_manager = DatabaseManager()
        self.packet_capture = PacketCapture(self.config, self.db_manager)
        self.detection_engine = ThreatDetectionEngine(self.config, self.db_manager)
        self.dashboard = WebDashboard(self.db_manager, self.detection_engine)
        self.running = False
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_threat_detector.log'),
                logging.StreamHandler()
            ]
        )
        
        # Signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logging.info("Shutting down...")
        self.stop()
        sys.exit(0)
    
    def start(self, interface: str = None, dashboard_port: int = 8080):
        """Start the threat detection system"""
        logging.info("Starting Network Threat Detection System")
        
        try:
            # Start packet capture
            self.packet_capture.start_capture(interface)
            
            # Start dashboard in separate thread
            dashboard_thread = threading.Thread(
                target=self.dashboard.run, 
                kwargs={'port': dashboard_port},
                daemon=True
            )
            dashboard_thread.start()
            
            self.running = True
            logging.info(f"Dashboard started on http://127.0.0.1:{dashboard_port}")
            
            # Main processing loop
            self.processing_loop()
            
        except Exception as e:
            logging.error(f"Error starting system: {e}")
            self.stop()
    
    def processing_loop(self):
        """Main packet processing loop"""
        packet_buffer = []
        last_analysis = time.time()
        
        while self.running:
            try:
                # Get packets from queue
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    packet_buffer.append(packet)
                except queue.Empty:
                    continue
                
                # Analyze packets periodically
                current_time = time.time()
                if current_time - last_analysis > 10:  # Analyze every 10 seconds
                    if packet_buffer:
                        threats = self.detection_engine.analyze_packets(packet_buffer)
                        if threats:
                            for threat in threats:
                                logging.warning(f"Threat detected: {threat.threat_type} from {threat.src_ip}")
                        
                        packet_buffer.clear()
                        last_analysis = current_time
                
            except Exception as e:
                logging.error(f"Error in processing loop: {e}")
                time.sleep(1)
    
    def stop(self):
        """Stop the threat detection system"""
        self.running = False
        self.packet_capture.stop_capture()
        logging.info("Network Threat Detection System stopped")
    
    def generate_report(self, hours: int = 24) -> str:
        """Generate comprehensive threat report"""
        threats = self.db_manager.get_recent_threats(hours)
        
        report = f"""
Network Threat Detection Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Period: Last {hours} hours

SUMMARY:
- Total Threats: {len(threats)}
- High Severity: {len([t for t in threats if t['severity'] == 'HIGH'])}
- Medium Severity: {len([t for t in threats if t['severity'] == 'MEDIUM'])}
- Critical Severity: {len([t for t in threats if t['severity'] == 'CRITICAL'])}

DETAILED THREATS:
"""
        
        for threat in threats[:20]:  # Top 20 threats
            report += f"""
{threat['threat_type']} - {threat['severity']}
Time: {threat['timestamp']}
Source: {threat['src_ip']} -> {threat['dst_ip']}
Description: {threat['description']}
Confidence: {threat['confidence']:.2%}
---
"""
        
        return report

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Advanced Network Threat Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Dashboard port')
    parser.add_argument('-r', '--report', action='store_true', help='Generate report only')
    parser.add_argument('--scan-threshold', type=int, default=50, help='Port scan threshold')
    parser.add_argument('--ddos-threshold', type=int, default=1000, help='DDoS threshold')
    
    args = parser.parse_args()
    
    # Create custom config
    config = ThreatConfig(
        scan_threshold=args.scan_threshold,
        ddos_threshold=args.ddos_threshold
    )
    
    # Initialize detector
    detector = NetworkThreatDetector(config)
    
    if args.report:
        print(detector.generate_report())
        return
    
    try:
        detector.start(interface=args.interface, dashboard_port=args.port)
    except KeyboardInterrupt:
        detector.stop()

if __name__ == "__main__":
    main()
