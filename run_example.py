#!/usr/bin/env python3
"""
Example usage and demonstration script for Network Threat Detection System
"""

import time
import threading
import requests
from network_threat_detector import NetworkThreatDetector, ThreatConfig

def demo_monitoring():
    """Demonstrate the monitoring capabilities"""
    print("=== Network Threat Detection System Demo ===\n")
    
    # Create custom configuration for demo
    config = ThreatConfig(
        scan_threshold=10,      # Lower threshold for demo
        ddos_threshold=100,     # Lower threshold for demo
        anomaly_contamination=0.15,
        window_size=60          # 1 minute window
    )
    
    # Initialize detector
    detector = NetworkThreatDetector(config)
    
    print("Starting threat detection system...")
    print("Dashboard will be available at: http://localhost:8080")
    print("Press Ctrl+C to stop monitoring\n")
    
    try:
        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=detector.start,
            kwargs={'dashboard_port': 8080},
            daemon=True
        )
        monitor_thread.start()
        
        # Wait for dashboard to start
        time.sleep(3)
        
        # Check if dashboard is accessible
        try:
            response = requests.get('http://localhost:8080/api/statistics', timeout=5)
            print("Dashboard is running and accessible!")
        except:
            print("Dashboard starting up...")
        
        # Keep running
        while True:
            time.sleep(10)
            # You could add periodic status checks here
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        detector.stop()
        print("Demo completed!")

def generate_sample_report():
    """Generate a sample threat report"""
    print("=== Generating Sample Threat Report ===\n")
    
    detector = NetworkThreatDetector()
    report = detector.generate_report(hours=24)
    
    print(report)
    
    # Save report to file
    with open('threat_report.txt', 'w') as f:
        f.write(report)
    
    print("\nReport saved to: threat_report.txt")

def test_configuration():
    """Test different configuration options"""
    print("=== Testing Configuration Options ===\n")
    
    # Test different configurations
    configs = [
        ("Default", ThreatConfig()),
        ("High Sensitivity", ThreatConfig(scan_threshold=20, ddos_threshold=500)),
        ("Low Sensitivity", ThreatConfig(scan_threshold=100, ddos_threshold=2000)),
    ]
    
    for name, config in configs:
        print(f"\n{name} Configuration:")
        print(f"  Scan Threshold: {config.scan_threshold}")
        print(f"  DDoS Threshold: {config.ddos_threshold}")
        print(f"  Anomaly Contamination: {config.anomaly_contamination}")
        print(f"  Window Size: {config.window_size} seconds")

if __name__ == "__main__":
    print("Network Threat Detection System - Demo Options")
    print("1. Start Monitoring (Full Demo)")
    print("2. Generate Sample Report")
    print("3. Test Configuration Options")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == "1":
        demo_monitoring()
    elif choice == "2":
        generate_sample_report()
    elif choice == "3":
        test_configuration()
    else:
        print("Invalid choice. Running demo monitoring...")
        demo_monitoring()
