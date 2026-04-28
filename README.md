# Network Threat Detection System

**MIT-grade professional cybersecurity tool for real-time network monitoring and intelligent threat detection**

## Overview

This advanced network threat detection system combines multiple sophisticated algorithms to identify and analyze network security threats in real-time. Built with professional-grade architecture, it's designed to impress organizations like MIT with its comprehensive approach to cybersecurity.

## Features

### Core Capabilities
- **Real-time Packet Capture**: Advanced packet sniffing using Scapy
- **Multi-algorithm Threat Detection**: 
  - Port scan detection
  - DDoS attack detection  
  - Machine learning-based anomaly detection
  - Suspicious port access monitoring
- **Intelligent Analysis**: Isolation Forest and DBSCAN clustering algorithms
- **Professional Dashboard**: Real-time web interface with live statistics
- **Comprehensive Logging**: SQLite database for persistent storage

### Advanced Features
- **Statistical Analysis**: Network traffic pattern analysis
- **Threat Scoring**: Confidence-based threat assessment
- **Automated Reporting**: Detailed threat intelligence reports
- **Whitelist Management**: Configurable IP whitelisting
- **Customizable Thresholds**: Adaptive detection parameters

## Installation

### Prerequisites
- Python 3.8 or higher
- Administrative privileges (for packet capture)
- Network interface access

### Setup
```bash
# Clone or download the files
git clone <repository-url>
cd network-threat-detector

# Install dependencies
pip install -r requirements.txt

# For Linux systems, may need additional packages:
sudo apt-get install libpcap-dev tcpdump
```

## Quick Start (Windows)

### Notes

- **PowerShell runs executables from the current directory only with `./`**.
  - Example: run `install.bat` as `./install.bat`.
- **Real packet capture typically requires Administrator** on Windows (Npcap/WinPcap driver access).

### Option A: Threat detector (main app)

```bash
python network_threat_detector.py
```

Dashboard:

`http://localhost:8080`

Administrator start helper:

```bash
./run_as_admin.bat
```

### Option B: Ultra real-time live packet monitor

This is a dedicated live monitor UI focused on packet streaming.

```bash
./start_real_time.bat
```

### Option C: Simple demo dashboard (no sniff required)

If you just want to see the UI running quickly:

```bash
python simple_monitor.py
```

## Usage

### Basic Usage
```bash
# Start with default settings
python network_threat_detector.py

# Specify network interface
python network_threat_detector.py -i eth0

# Custom dashboard port
python network_threat_detector.py -p 9090

# Generate report only
python network_threat_detector.py --report
```

### Advanced Configuration
```bash
# Custom detection thresholds
python network_threat_detector.py --scan-threshold 30 --ddos-threshold 500
```

## Web Dashboard

Access the real-time dashboard at `http://localhost:8080`

### Dashboard Features
- **Live Statistics**: Total packets, unique IPs, recent threats
- **Protocol Distribution**: Visual breakdown of network protocols
- **Threat Timeline**: Real-time threat event visualization
- **Detailed Threat List**: Comprehensive threat information with confidence scores

## Threat Detection Algorithms

### 1. Port Scan Detection
- Monitors unique port access attempts per IP
- Configurable threshold for scan detection
- Tracks TCP SYN packets across multiple ports

### 2. DDoS Detection
- Time-based packet frequency analysis
- Sliding window algorithm for attack detection
- Adjustable sensitivity parameters

### 3. Machine Learning Anomaly Detection
- **Isolation Forest**: Unsupervised anomaly detection
- **DBSCAN Clustering**: Traffic pattern clustering
- Feature extraction from packet metadata
- Real-time scoring and classification

### 4. Suspicious Port Monitoring
- Predefined suspicious port list (22, 23, 80, 443, 3389, etc.)
- Protocol-specific threat assessment
- Configurable port whitelist

## Architecture

```
Network Threat Detector
    |
    |-- Packet Capture Engine (Scapy)
    |-- Database Manager (SQLite)
    |-- Threat Detection Engine
    |   |-- Port Scan Detector
    |   |-- DDoS Detector  
    |   |-- ML Anomaly Detector
    |   |-- Suspicious Port Monitor
    |-- Web Dashboard (Flask)
    |-- Reporting System
```

## Configuration

### ThreatConfig Parameters
```python
@dataclass
class ThreatConfig:
    scan_threshold: int = 50          # Port scan threshold
    ddos_threshold: int = 1000        # DDoS threshold  
    anomaly_contamination: float = 0.1 # ML anomaly contamination
    window_size: int = 300            # Time window (seconds)
    max_connections: int = 100         # Max connections per IP
    suspicious_ports: Set[int]         # Suspicious ports set
    whitelist_ips: Set[str]            # Whitelisted IPs
```

## Database Schema

### Tables
- **packets**: Raw packet data storage
- **threats**: Detected threat events
- **statistics**: Network statistics aggregation

## Logging

Comprehensive logging system:
- File logging: `network_threat_detector.log`
- Console output for real-time monitoring
- Structured log format with timestamps

## Performance

### Optimizations
- Asynchronous packet processing
- Queue-based architecture
- Memory-efficient data structures
- Configurable buffer sizes

### Resource Requirements
- **CPU**: Moderate (packet processing)
- **Memory**: ~100MB (depends on traffic)
- **Storage**: SQLite database (grows with traffic)

## Security Considerations

### Permissions
- Requires administrative/root privileges for packet capture
- Network interface access permissions
- Database file permissions

### Data Privacy
- All data stored locally
- No external data transmission
- Configurable data retention policies

## Troubleshooting

### Common Issues
1. **Permission Denied**: Run with administrator privileges
2. **No Interface Found**: Check available network interfaces
3. **Port Already in Use**: Change dashboard port with `-p` flag

### Debug Mode
```bash
# Enable debug logging
python network_threat_detector.py --debug
```

## API Endpoints

### REST API
- `GET /` - Main dashboard
- `GET /api/threats` - Recent threats (JSON)
- `GET /api/statistics` - Network statistics (JSON)
- `GET /api/stop` - Stop monitoring

## Repo Contents

- **`network_threat_detector.py`**
  - Main application (capture + detection + dashboard)
- **`run_as_admin.bat`**
  - Starts the main app with Administrator privileges on Windows
- **`real_time_capture.py`**
  - Separate live-capture focused dashboard (real-time packet stream UI)
- **`start_real_time.bat`**
  - Starts `real_time_capture.py` as Administrator and opens the dashboard
- **`simple_monitor.py`**
  - Simple demo dashboard (useful for UI/dev without sniff permissions)
- **`requirements.txt`**
  - Python dependencies

## Contributing

This is a professional-grade cybersecurity tool. When contributing:
- Follow PEP 8 coding standards
- Add comprehensive documentation
- Include unit tests
- Maintain security best practices

## License

This project is provided for educational and professional development purposes. Use responsibly and in accordance with applicable laws and regulations.

## Disclaimer

This tool is designed for legitimate security testing and monitoring purposes only. Users are responsible for ensuring compliance with local laws and obtaining proper authorization before monitoring network traffic.

---

**Author**: Professional Security Analyst  
**Version**: 1.0.0  
**Target**: MIT-grade cybersecurity demonstration
