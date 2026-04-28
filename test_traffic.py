#!/usr/bin/env python3
"""
Test traffic generator for Network Threat Detection System
Creates simulated network traffic to demonstrate the system
"""

import time
import sqlite3
import random
from datetime import datetime, timedelta
from network_threat_detector import NetworkPacket, ThreatEvent, DatabaseManager

def generate_test_packets():
    """Generate test network packets"""
    db = DatabaseManager()
    
    # Test IPs
    test_ips = [
        "192.168.1.100", "192.168.1.101", "10.0.0.50",
        "172.16.0.25", "203.0.113.10", "198.51.100.5"
    ]
    
    # External IPs
    external_ips = [
        "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"
    ]
    
    protocols = ["TCP", "UDP", "ICMP"]
    ports = [80, 443, 22, 53, 3389, 1433, 3306, 25, 110, 995]
    
    packets = []
    
    # Generate normal traffic
    for i in range(100):
        packet = NetworkPacket(
            timestamp=time.time() - random.randint(0, 3600),
            src_ip=random.choice(test_ips),
            dst_ip=random.choice(external_ips),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice(ports),
            protocol=random.choice(protocols),
            packet_size=random.randint(64, 1500),
            payload_size=random.randint(0, 1200),
            flags="SYN" if random.random() > 0.7 else "ACK",
            ttl=random.randint(32, 128),
            packet_hash=f"test_{i}_{random.randint(1000, 9999)}"
        )
        packets.append(packet)
        db.store_packet(packet)
    
    # Generate port scan traffic
    scanner_ip = "203.0.113.10"
    for port in range(1, 101):  # Scan 100 ports
        packet = NetworkPacket(
            timestamp=time.time() - random.randint(0, 1800),
            src_ip=scanner_ip,
            dst_ip="192.168.1.100",
            src_port=random.randint(1024, 65535),
            dst_port=port,
            protocol="TCP",
            packet_size=random.randint(64, 128),
            payload_size=0,
            flags="SYN",
            ttl=64,
            packet_hash=f"scan_{port}_{random.randint(1000, 9999)}"
        )
        packets.append(packet)
        db.store_packet(packet)
    
    # Generate DDoS-like traffic
    attacker_ip = "198.51.100.5"
    target_ip = "192.168.1.101"
    for i in range(150):  # 150 packets in short time
        packet = NetworkPacket(
            timestamp=time.time() - random.randint(0, 300),  # Last 5 minutes
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=random.randint(1024, 65535),
            dst_port=80,
            protocol="TCP",
            packet_size=random.randint(64, 256),
            payload_size=random.randint(0, 100),
            flags="SYN",
            ttl=random.randint(32, 64),
            packet_hash=f"ddos_{i}_{random.randint(1000, 9999)}"
        )
        packets.append(packet)
        db.store_packet(packet)
    
    # Generate suspicious port access
    suspicious_ports = [22, 23, 3389, 1433, 3306]
    for port in suspicious_ports:
        packet = NetworkPacket(
            timestamp=time.time() - random.randint(0, 7200),
            src_ip="172.16.0.25",
            dst_ip="192.168.1.100",
            src_port=random.randint(1024, 65535),
            dst_port=port,
            protocol="TCP",
            packet_size=64,
            payload_size=0,
            flags="SYN",
            ttl=64,
            packet_hash=f"suspicious_{port}_{random.randint(1000, 9999)}"
        )
        packets.append(packet)
        db.store_packet(packet)
    
    print(f"Generated {len(packets)} test packets")
    return packets

def generate_test_threats():
    """Generate test threat events"""
    db = DatabaseManager()
    
    threats = [
        ThreatEvent(
            event_id="PORT_SCAN_TEST_001",
            timestamp=datetime.now() - timedelta(minutes=15),
            threat_type="PORT_SCAN",
            severity="HIGH",
            src_ip="203.0.113.10",
            dst_ip="192.168.1.100",
            description="Port scan detected from 203.0.113.10. Scanned 100 ports.",
            raw_data={'scanned_ports': list(range(1, 101))},
            confidence=0.95
        ),
        ThreatEvent(
            event_id="DDOS_TEST_001",
            timestamp=datetime.now() - timedelta(minutes=5),
            threat_type="DDOS",
            severity="CRITICAL",
            src_ip="198.51.100.5",
            dst_ip="192.168.1.101",
            description="DDoS attack detected from 198.51.100.5. 150 packets in 300 seconds.",
            raw_data={'packet_count': 150, 'time_window': 300},
            confidence=0.88
        ),
        ThreatEvent(
            event_id="SUSPICIOUS_PORT_TEST_001",
            timestamp=datetime.now() - timedelta(hours=2),
            threat_type="SUSPICIOUS_PORT_ACCESS",
            severity="MEDIUM",
            src_ip="172.16.0.25",
            dst_ip="192.168.1.100",
            description="Access to suspicious port 22 (TCP)",
            raw_data={'port': 22, 'protocol': 'TCP'},
            confidence=0.65
        ),
        ThreatEvent(
            event_id="ANOMALY_TEST_001",
            timestamp=datetime.now() - timedelta(minutes=30),
            threat_type="ANOMALY",
            severity="MEDIUM",
            src_ip="10.0.0.50",
            dst_ip="8.8.8.8",
            description="Anomalous traffic detected from 10.0.0.50 to 8.8.8.8",
            raw_data={'features': [1500, 1200, 64, 3, 50, 8, 1], 'anomaly_score': -1.0},
            confidence=0.72
        )
    ]
    
    for threat in threats:
        db.store_threat(threat)
    
    print(f"Generated {len(threats)} test threats")
    return threats

def main():
    """Main test function"""
    print("=== Network Threat Detection System - Test Data Generator ===\n")
    
    print("Generating test packets...")
    packets = generate_test_packets()
    
    print("Generating test threats...")
    threats = generate_test_threats()
    
    print("\nTest data generation completed!")
    print("Now you can:")
    print("1. Run: python network_threat_detector.py")
    print("2. Open: http://localhost:8080")
    print("3. Check the dashboard for live data")
    
    # Show summary
    db = DatabaseManager()
    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM packets')
    packet_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM threats')
    threat_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT protocol, COUNT(*) FROM packets GROUP BY protocol')
    protocols = dict(cursor.fetchall())
    
    conn.close()
    
    print(f"\nDatabase Summary:")
    print(f"- Total Packets: {packet_count}")
    print(f"- Total Threats: {threat_count}")
    print(f"- Protocols: {protocols}")

if __name__ == "__main__":
    main()
