#!/usr/bin/env python3
"""
Real-time Network Traffic Simulator
Creates realistic network traffic for demonstration
"""

import time
import random
import threading
import sqlite3
from datetime import datetime
from network_threat_detector import NetworkPacket, DatabaseManager

class RealTimeSimulator:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.running = False
        self.simulation_thread = None
        
        # Realistic IP ranges
        self.local_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.50", "10.0.0.51", "172.16.0.25"
        ]
        
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9",
            "93.184.216.34", "151.101.1.69", "104.21.8.7"
        ]
        
        self.protocols = ["TCP", "UDP", "ICMP"]
        self.ports = [80, 443, 22, 53, 3389, 1433, 3306, 25, 110, 995, 21, 23]
        
    def generate_realistic_packet(self) -> NetworkPacket:
        """Generate realistic network packet"""
        packet_type = random.choice(['web', 'dns', 'ssh', 'mail', 'ping', 'general'])
        
        if packet_type == 'web':
            src_ip = random.choice(self.local_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice([80, 443])
            protocol = "TCP"
            packet_size = random.randint(1200, 1500)
            payload_size = random.randint(800, 1200)
            flags = random.choice(["SYN", "ACK", "PSH", "FIN"])
            
        elif packet_type == 'dns':
            src_ip = random.choice(self.local_ips)
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "208.67.222.222"])
            dst_port = 53
            protocol = "UDP"
            packet_size = random.randint(64, 512)
            payload_size = random.randint(32, 256)
            flags = ""
            
        elif packet_type == 'ssh':
            src_ip = random.choice(self.local_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = 22
            protocol = "TCP"
            packet_size = random.randint(64, 256)
            payload_size = random.randint(32, 128)
            flags = random.choice(["SYN", "ACK", "PSH"])
            
        elif packet_type == 'mail':
            src_ip = random.choice(self.local_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice([25, 110, 995])
            protocol = "TCP"
            packet_size = random.randint(512, 1024)
            payload_size = random.randint(256, 800)
            flags = random.choice(["SYN", "ACK", "PSH"])
            
        elif packet_type == 'ping':
            src_ip = random.choice(self.local_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = 0
            protocol = "ICMP"
            packet_size = random.randint(64, 128)
            payload_size = random.randint(32, 64)
            flags = ""
            
        else:  # general
            src_ip = random.choice(self.local_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice(self.ports)
            protocol = random.choice(["TCP", "UDP"])
            packet_size = random.randint(64, 1500)
            payload_size = random.randint(0, min(packet_size - 20, 1200))
            flags = "SYN" if protocol == "TCP" and random.random() > 0.5 else ""
        
        return NetworkPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            payload_size=payload_size,
            flags=flags,
            ttl=random.randint(32, 128),
            packet_hash=f"sim_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
        )
    
    def simulation_loop(self):
        """Main simulation loop"""
        packet_count = 0
        
        while self.running:
            # Generate variable packet rate (1-5 packets per second)
            packet_rate = random.randint(1, 5)
            
            for _ in range(packet_rate):
                if not self.running:
                    break
                
                packet = self.generate_realistic_packet()
                self.db_manager.store_packet(packet)
                packet_count += 1
                
                # Small delay between packets
                time.sleep(random.uniform(0.05, 0.3))
            
            # Wait before next burst
            time.sleep(random.uniform(0.5, 2.0))
            
            # Print status every 50 packets
            if packet_count % 50 == 0:
                print(f"Generated {packet_count} packets...")
    
    def start(self):
        """Start the simulation"""
        self.running = True
        self.simulation_thread = threading.Thread(target=self.simulation_loop, daemon=True)
        self.simulation_thread.start()
        print("Real-time network simulation started!")
    
    def stop(self):
        """Stop the simulation"""
        self.running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=2)
        print("Real-time network simulation stopped!")

def main():
    """Main function to run simulator"""
    print("=== Real-time Network Traffic Simulator ===\n")
    
    db_manager = DatabaseManager()
    simulator = RealTimeSimulator(db_manager)
    
    try:
        simulator.start()
        
        print("Generating realistic network traffic...")
        print("Open http://localhost:8080 to see live packets!")
        print("Press Ctrl+C to stop simulation\n")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping simulation...")
        simulator.stop()

if __name__ == "__main__":
    main()
