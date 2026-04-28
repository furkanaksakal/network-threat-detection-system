#!/usr/bin/env python3
"""
Simple Real-time Network Monitor
Fixed version for immediate testing
"""

import time
import threading
import sqlite3
import logging
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SimpleMonitor:
    def __init__(self):
        self.app = Flask(__name__)
        self.db_path = "simple_monitor.db"
        self.init_database()
        self.packets_count = 0
        self.start_time = time.time()
        self.setup_routes()
        
    def init_database(self):
        """Initialize database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
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
                info TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logging.info("Database initialized")
    
    def generate_sample_packet(self):
        """Generate sample packet for testing"""
        import random
        
        src_ips = ["192.168.1.100", "192.168.1.101", "10.0.0.50"]
        dst_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "172.217.16.14"]  # Google, Cloudflare, OpenDNS, YouTube
        
        packet = {
            'timestamp': time.time(),
            'src_ip': random.choice(src_ips),
            'dst_ip': random.choice(dst_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 22, 3306]),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'packet_size': random.randint(64, 1500),
            'info': f"Sample packet {self.packets_count}"
        }
        
        return packet
    
    def add_sample_packets(self):
        """Add sample packets to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Add 100 sample packets
        for i in range(100):
            packet = self.generate_sample_packet()
            
            cursor.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (packet['timestamp'], packet['src_ip'], packet['dst_ip'], 
                  packet['src_port'], packet['dst_port'], packet['protocol'], 
                  packet['packet_size'], packet['info']))
            
            self.packets_count += 1
        
        conn.commit()
        conn.close()
        logging.info(f"Added {self.packets_count} sample packets")
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard"""
            return self.generate_dashboard_html()
        
        @self.app.route('/api/packets')
        def get_packets():
            """Get packets API"""
            limit = request.args.get('limit', 1000, type=int)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, info
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
                    'info': row[7]
                })
            
            conn.close()
            return jsonify(packets)
        
        @self.app.route('/api/statistics')
        def get_statistics():
            """Get statistics API"""
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM packets')
            total_packets = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM packets')
            unique_ips = cursor.fetchone()[0]
            
            cursor.execute('SELECT protocol, COUNT(*) FROM packets GROUP BY protocol')
            protocols = dict(cursor.fetchall())
            
            cursor.execute('SELECT COUNT(*) FROM packets WHERE timestamp > ?', (time.time() - 60,))
            recent_packets = cursor.fetchone()[0]
            
            conn.close()
            
            return jsonify({
                'total_packets': total_packets,
                'unique_ips': unique_ips,
                'protocols': protocols,
                'recent_packets': recent_packets,
                'packets_per_minute': recent_packets
            })
        
        @self.app.route('/api/add-traffic')
        def add_traffic():
            """Add more traffic for testing"""
            self.add_sample_packets()
            return jsonify({'status': 'success', 'packets_added': 100})
    
    def generate_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Simple Network Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; text-align: center; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 5px; flex: 1; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .packets { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .packet-controls { margin-bottom: 15px; }
        .packet-controls button { margin-right: 10px; padding: 8px 15px; background: #3498db; color: white; border: none; border-radius: 3px; cursor: pointer; }
        .packet-controls button:hover { background: #2980b9; }
        .packet-table-container { max-height: 500px; overflow-y: auto; border: 1px solid #ddd; }
        .packet-table { width: 100%; border-collapse: collapse; font-family: 'Courier New', monospace; font-size: 12px; }
        .packet-table th { background: #34495e; color: white; padding: 10px; text-align: left; position: sticky; top: 0; }
        .packet-table td { padding: 6px 8px; border-bottom: 1px solid #ecf0f1; }
        .packet-table tr:hover { background: #f8f9fa; }
        .packet-table tr.tcp { color: #2c3e50; }
        .packet-table tr.udp { color: #27ae60; }
        .packet-table tr.icmp { color: #e74c3c; }
        .status { background: #e8f5e8; padding: 10px; border-radius: 5px; margin: 10px 0; text-align: center; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SIMPLE NETWORK MONITOR</h1>
        <p>Real-time packet visualization</p>
    </div>
    
    <div class="status" id="status">
        MONITOR ACTIVE - Ready to capture traffic
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3 id="total-packets">0</h3>
            <p>Total Packets</p>
        </div>
        <div class="stat-card">
            <h3 id="recent-packets">0</h3>
            <p>Recent Packets</p>
        </div>
        <div class="stat-card">
            <h3 id="unique-ips">0</h3>
            <p>Unique IPs</p>
        </div>
        <div class="stat-card">
            <h3 id="protocols-count">0</h3>
            <p>Protocols</p>
        </div>
    </div>
    
    <div class="packets">
        <h2>PACKET CAPTURE</h2>
        <div class="packet-controls">
            <button onclick="refreshData()">Refresh</button>
            <button onclick="addTraffic()">Add Traffic</button>
            <button onclick="clearPackets()">Clear</button>
            <button onclick="toggleAutoScroll()">Auto Scroll: <span id="scroll-status">ON</span></button>
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
        
        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            document.getElementById('scroll-status').textContent = autoScroll ? 'ON' : 'OFF';
        }
        
        function clearPackets() {
            document.getElementById('packet-list').innerHTML = '';
        }
        
        function addTraffic() {
            fetch('/api/add-traffic')
                .then(response => response.json())
                .then(data => {
                    console.log('Added traffic:', data);
                    refreshData();
                });
        }
        
        function refreshData() {
            // Update packets
            fetch('/api/packets?limit=1000')
                .then(response => response.json())
                .then(packets => {
                    const packetList = document.getElementById('packet-list');
                    packetList.innerHTML = '';
                    
                    packets.forEach(packet => {
                        const row = document.createElement('tr');
                        row.className = packet.protocol.toLowerCase();
                        
                        const srcPort = packet.src_port > 0 ? `:${packet.src_port}` : '';
                        const dstPort = packet.dst_port > 0 ? `:${packet.dst_port}` : '';
                        const src = `${packet.src_ip}${srcPort}`;
                        const dst = `${packet.dst_ip}${dstPort}`;
                        
                        row.innerHTML = `
                            <td>${packet.time_formatted}</td>
                            <td>${src}</td>
                            <td>${dst}</td>
                            <td>${packet.protocol}</td>
                            <td>${packet.packet_size}</td>
                            <td>${packet.info}</td>
                        `;
                        
                        packetList.appendChild(row);
                    });
                    
                    if (autoScroll) {
                        const container = document.querySelector('.packet-table-container');
                        container.scrollTop = container.scrollHeight;
                    }
                });
            
            // Update statistics
            fetch('/api/statistics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();
                    document.getElementById('recent-packets').textContent = data.recent_packets.toLocaleString();
                    document.getElementById('unique-ips').textContent = data.unique_ips.toLocaleString();
                    document.getElementById('protocols-count').textContent = Object.keys(data.protocols).length;
                    
                    const status = document.getElementById('status');
                    status.textContent = `MONITOR ACTIVE - ${data.total_packets} packets captured`;
                });
        }
        
        // Initial load
        refreshData();
        
        // Auto refresh every 2 seconds
        setInterval(refreshData, 2000);
    </script>
</body>
</html>
        '''
    
    def run(self, host='127.0.0.1', port=8080, debug=False):
        """Run the monitor"""
        logging.info(f"Starting Simple Network Monitor on http://{host}:{port}")
        
        # Add initial sample data
        self.add_sample_packets()
        
        # Run Flask app
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Main function"""
    print("=== SIMPLE NETWORK MONITOR ===")
    print("Starting monitor...")
    
    try:
        monitor = SimpleMonitor()
        monitor.run()
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Error starting monitor: {e}")

if __name__ == "__main__":
    main()
