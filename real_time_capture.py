#!/usr/bin/env python3
"""
Real-time Network Traffic Capture with Live Updates
Captures actual network traffic and updates dashboard in real-time
"""

import os
import sys
import time
import threading
import queue
import sqlite3
import logging
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List
import socket
import struct
import hashlib

# Third-party imports
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from flask import Flask, jsonify, render_template_string, request

@dataclass
class LivePacket:
    """Live network packet structure"""
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
    
    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp,
            'time_formatted': datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S.%f')[:-3],
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'payload_size': self.payload_size,
            'flags': self.flags,
            'ttl': self.ttl,
            'packet_hash': self.packet_hash
        }

class LiveNetworkCapture:
    """Real-time network packet capture system"""
    
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packets_buffer = []
        self.running = False
        self.capture_thread = None
        self.db_path = "live_traffic.db"
        self.init_database()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, 
                          format='%(asctime)s - %(levelname)s - %(message)s')
        
    def init_database(self):
        """Initialize SQLite database for packet storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS live_packets (
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
        
        conn.commit()
        conn.close()
    
    def packet_hash(self, packet) -> str:
        """Generate unique hash for packet"""
        hash_input = f"{packet.time}{len(packet)}"
        return hashlib.md5(hash_input.encode()).hexdigest()
    
    def extract_packet_info(self, packet) -> Optional[LivePacket]:
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
            
            return LivePacket(
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
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        if not self.running:
            return
        
        packet_info = self.extract_packet_info(packet)
        if packet_info:
            try:
                self.packet_queue.put_nowait(packet_info)
                self.packets_buffer.append(packet_info)
                
                # Keep buffer size manageable
                if len(self.packets_buffer) > 50000:
                    self.packets_buffer = self.packets_buffer[-25000:]
                
                # Store in database
                self.store_packet(packet_info)
                
            except queue.Full:
                # Queue is full, remove oldest packet
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(packet_info)
                except queue.Empty:
                    pass
    
    def store_packet(self, packet: LivePacket):
        """Store packet in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO live_packets (timestamp, src_ip, dst_ip, src_port, dst_port,
                                   protocol, packet_size, payload_size, flags, ttl, packet_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (packet.timestamp, packet.src_ip, packet.dst_ip, packet.src_port,
              packet.dst_port, packet.protocol, packet.packet_size, packet.payload_size,
              packet.flags, packet.ttl, packet.packet_hash))
        conn.commit()
        conn.close()
    
    def get_recent_packets(self, limit: int = 10000) -> List[dict]:
        """Get recent packets from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
                   packet_size, payload_size, flags, ttl, packet_hash
            FROM live_packets 
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
        return packets
    
    def get_live_packets(self, limit: int = 1000) -> List[dict]:
        """Get live packets from buffer"""
        recent_packets = self.packets_buffer[-limit:] if len(self.packets_buffer) > limit else self.packets_buffer
        return [packet.to_dict() for packet in recent_packets]
    
    def start_capture(self, interface: str = None):
        """Start packet capture"""
        try:
            if interface is None:
                interfaces = scapy.get_if_list()
                if not interfaces:
                    raise Exception("No network interfaces available")
                interface = interfaces[0]
                logging.info(f"Using interface: {interface}")
            
            self.running = True
            self.capture_thread = threading.Thread(
                target=self._capture_loop, 
                args=(interface,),
                daemon=True
            )
            self.capture_thread.start()
            logging.info(f"Started packet capture on interface: {interface}")
            
        except Exception as e:
            logging.error(f"Error starting capture: {e}")
            raise
    
    def _capture_loop(self, interface: str):
        """Main capture loop"""
        try:
            scapy.sniff(iface=interface, prn=self.packet_handler, 
                       store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            logging.error(f"Capture error: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logging.info("Stopped packet capture")

class RealTimeDashboard:
    """Real-time dashboard for live packet capture"""
    
    def __init__(self, capture_system: LiveNetworkCapture):
        self.app = Flask(__name__)
        self.capture = capture_system
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard"""
            return self.generate_dashboard_html()
        
        @self.app.route('/api/live-packets')
        def get_live_packets():
            """Get live packets API"""
            limit = request.args.get('limit', 1000, type=int)
            packets = self.capture.get_live_packets(limit)
            return jsonify(packets)
        
        @self.app.route('/api/recent-packets')
        def get_recent_packets():
            """Get recent packets from database"""
            limit = request.args.get('limit', 10000, type=int)
            packets = self.capture.get_recent_packets(limit)
            return jsonify(packets)
        
        @self.app.route('/api/statistics')
        def get_statistics():
            """Get capture statistics"""
            conn = sqlite3.connect(self.capture.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM live_packets')
            total_packets = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM live_packets')
            unique_src_ips = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT dst_ip) FROM live_packets')
            unique_dst_ips = cursor.fetchone()[0]
            
            cursor.execute('SELECT protocol, COUNT(*) FROM live_packets GROUP BY protocol')
            protocols = dict(cursor.fetchall())
            
            cursor.execute('SELECT COUNT(*) FROM live_packets WHERE timestamp > ?', (time.time() - 60,))
            packets_last_minute = cursor.fetchone()[0]
            
            conn.close()
            
            return jsonify({
                'total_packets': total_packets,
                'unique_src_ips': unique_src_ips,
                'unique_dst_ips': unique_dst_ips,
                'protocols': protocols,
                'packets_last_minute': packets_last_minute,
                'capture_rate': packets_last_minute / 60.0
            })
    
    def generate_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Real-time Network Monitor</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; text-align: center; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 5px; flex: 1; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .packets { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .packet-controls { margin-bottom: 15px; }
        .packet-controls button { margin-right: 10px; padding: 8px 15px; background: #3498db; color: white; border: none; border-radius: 3px; cursor: pointer; font-weight: bold; }
        .packet-controls button:hover { background: #2980b9; }
        .packet-controls input { padding: 8px; border: 1px solid #ddd; border-radius: 3px; width: 120px; }
        .packet-table-container { max-height: 600px; overflow-y: auto; border: 1px solid #ddd; }
        .packet-table { width: 100%; border-collapse: collapse; font-family: 'Courier New', monospace; font-size: 11px; }
        .packet-table th { background: #34495e; color: white; padding: 10px; text-align: left; position: sticky; top: 0; z-index: 10; }
        .packet-table td { padding: 6px 8px; border-bottom: 1px solid #ecf0f1; }
        .packet-table tr:hover { background: #f8f9fa; }
        .packet-table tr.tcp { color: #2c3e50; }
        .packet-table tr.udp { color: #27ae60; }
        .packet-table tr.icmp { color: #e74c3c; }
        .packet-table tr.other { color: #7f8c8d; }
        .status { background: #e8f5e8; padding: 10px; border-radius: 5px; margin: 10px 0; text-align: center; font-weight: bold; color: #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>REAL-TIME NETWORK MONITOR</h1>
        <p>Live packet capture - Every packet, every port, no limits</p>
    </div>
    
    <div class="status" id="status">
        CAPTURE ACTIVE - Watching all network traffic...
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3 id="total-packets">0</h3>
            <p>Total Packets</p>
        </div>
        <div class="stat-card">
            <h3 id="packets-min">0</h3>
            <p>Packets/Min</p>
        </div>
        <div class="stat-card">
            <h3 id="capture-rate">0.0</h3>
            <p>Capture Rate</p>
        </div>
        <div class="stat-card">
            <h3 id="unique-ips">0</h3>
            <p>Unique IPs</p>
        </div>
    </div>
    
    <div class="packets">
        <h2>LIVE PACKET CAPTURE (REAL-TIME)</h2>
        <div class="packet-controls">
            <button onclick="toggleAutoScroll()">Auto Scroll: <span id="scroll-status">ON</span></button>
            <button onclick="clearPackets()">Clear</button>
            <button onclick="toggleLiveMode()">Mode: <span id="mode-status">LIVE</span></button>
            <input type="number" id="packet-limit" value="5000" min="100" max="50000" placeholder="Packet limit">
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
    
    <script>
        let autoScroll = true;
        let liveMode = true;
        let lastPacketCount = 0;
        let updateInterval;
        
        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            document.getElementById('scroll-status').textContent = autoScroll ? 'ON' : 'OFF';
        }
        
        function toggleLiveMode() {
            liveMode = !liveMode;
            document.getElementById('mode-status').textContent = liveMode ? 'LIVE' : 'HISTORY';
        }
        
        function clearPackets() {
            document.getElementById('packet-list').innerHTML = '';
            lastPacketCount = 0;
        }
        
        function updatePackets() {
            const limit = document.getElementById('packet-limit').value || 5000;
            const endpoint = liveMode ? '/api/live-packets' : '/api/recent-packets';
            
            fetch(`${endpoint}?limit=${limit}`)
                .then(response => response.json())
                .then(packets => {
                    const packetList = document.getElementById('packet-list');
                    
                    // Always update for real-time feel
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
                    
                    // Auto scroll to bottom if enabled
                    if (autoScroll) {
                        const container = document.querySelector('.packet-table-container');
                        container.scrollTop = container.scrollHeight;
                    }
                });
        }
        
        function updateStats() {
            fetch('/api/statistics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();
                    document.getElementById('packets-min').textContent = data.packets_last_minute.toLocaleString();
                    document.getElementById('capture-rate').textContent = data.capture_rate.toFixed(1);
                    document.getElementById('unique-ips').textContent = (data.unique_src_ips + data.unique_dst_ips).toLocaleString();
                    
                    // Update status
                    const status = document.getElementById('status');
                    if (data.packets_last_minute > 0) {
                        status.textContent = `CAPTURE ACTIVE - ${data.packets_last_minute} packets in last minute`;
                        status.style.background = '#e8f5e8';
                        status.style.color = '#27ae60';
                    } else {
                        status.textContent = 'CAPTURE ACTIVE - Waiting for traffic...';
                        status.style.background = '#fff3cd';
                        status.style.color = '#856404';
                    }
                });
        }
        
        function updateAll() {
            updatePackets();
            updateStats();
        }
        
        // Start real-time updates
        updateAll();
        updateInterval = setInterval(updateAll, 200); // Update every 200ms for ultra-real-time
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            if (updateInterval) {
                clearInterval(updateInterval);
            }
        });
    </script>
</body>
</html>
        '''
    
    def run(self, host='127.0.0.1', port=8080, debug=False):
        """Run the dashboard"""
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Main function"""
    print("=== REAL-TIME NETWORK MONITOR ===")
    print("Starting live packet capture system...")
    print()
    
    try:
        # Initialize capture system
        capture = LiveNetworkCapture()
        
        # Start capture
        capture.start_capture()
        
        # Start dashboard
        dashboard = RealTimeDashboard(capture)
        
        print("Dashboard started at: http://localhost:8080")
        print("Press Ctrl+C to stop monitoring")
        print()
        print("Features:")
        print("- Real-time packet capture (200ms refresh)")
        print("- All ports monitored (1-65535)")
        print("- Unlimited packet display")
        print("- Live traffic analysis")
        print()
        
        # Run dashboard
        dashboard.run()
        
    except KeyboardInterrupt:
        print("\nStopping capture...")
        capture.stop_capture()
        print("System stopped.")
    except Exception as e:
        print(f"Error: {e}")
        print("Note: This may require administrator privileges for packet capture.")

if __name__ == "__main__":
    main()
