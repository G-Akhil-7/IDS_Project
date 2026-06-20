# IDS Project - Intrusion Detection System

## Project Overview

This project is a Network-Based Intrusion Detection System (IDS) developed using Python and Scapy. The main objective of this project is to monitor network traffic in real time and detect suspicious activities that may indicate potential cyber-attacks. The system captures live packets from the network, analyzes them, and generates alerts whenever malicious behavior is detected.

This project was developed as a learning-oriented cybersecurity project to understand packet analysis, network monitoring, and intrusion detection techniques.

## Features

* Real-time network packet sniffing
* Port Scan Detection
* SYN Flood Detection
* ICMP Flood Detection
* SQL Injection Detection
* Alert Logging
* Console-based monitoring and alert display

## Technologies Used

* Python 3
* Scapy
* Kali Linux
* Git & GitHub

## Project Structure

IDS_project/
├── app/
│ ├── alerts/
│ │ └── alerts.p
│ │
│ ├── detection/
│ │ ├── detector.py
│ │ └── rules.py
│ │
│ └── sniffer.py
│
├── logs/
│ └── alerts.log
├── run.py
├── requirements.txt
└── README.md

## How the System Works

### 1. Packet Capture
The IDS continuously captures live network packets using the Scapy library. Every packet passing through the monitored interface is collected for further analysis.

### 2. Packet Analysis
After capturing packets, the system extracts important information such as:
* Source IP Address
* Destination IP Address
* Protocol Information
* TCP Flags
* Packet Payload Data
This information is used to identify suspicious behavior.

### 3. Attack Detection
#### Port Scan Detection
The IDS monitors connection attempts to multiple ports from the same source IP address. If a host attempts to access several ports in a short period, the activity is flagged as a potential port scan.

#### SYN Flood Detection
The system tracks TCP SYN packets. When an unusually high number of SYN requests are received from the same source, the IDS generates a SYN Flood alert.

#### ICMP Flood Detectio
The IDS monitors ICMP Echo Requests (Ping packets). A large volume of ICMP packets within a short duration is treated as a possible ICMP Flood attack.

#### SQL Injection Detection
Packet payloads are inspected for common SQL Injection patterns such as:

* ' OR '1'='1
* UNION SELECT
* DROP TABLE

If these keywords or patterns are detected, an SQL Injection alert is generated.

## Alert Logging
All detected attacks are recorded in the log file:
logs/alerts.log

Example Alert Entries:

[2026-05-10 03:04:04] [ALERT] Possible Port Scan Detected from 127.0.0.1

[2026-05-10 03:05:11] [ALERT] Possible SYN Flood Detected from 127.0.0.1

[2026-05-10 03:06:15] [ALERT] Possible ICMP Flood Detected from 127.0.0.1

[2026-05-10 03:07:20] [ALERT] Possible SQL Injection Attempt from 127.0.0.1

## Testing and Results
The IDS was tested against multiple attack scenarios.

### Port Scan Testing
Tool Used: Nmap

Command:
nmap -p 1-1000 127.0.0.1

Result:
The IDS successfully detected port scanning activity and generated an alert.

### SYN Flood Testing
Tool Used: Hping3

Command:
sudo hping3 -S 127.0.0.1 -p 80 --flood

Result:
The IDS successfully detected excessive SYN packets and raised a SYN Flood alert.

### ICMP Flood Testing

Command:
ping -f 127.0.0.1

Result:
The IDS successfully detected ICMP Flood activity.

### SQL Injection Testing

Command:

curl "http://127.0.0.1:8080/?id=' OR '1'='1"

Result:

The IDS successfully identified SQL Injection patterns within packet payloads and generated alerts.

## Future Enhancements

The current version focuses on basic attack detection. Future improvements may include:

* Brute Force Attack Detection
* Rule-Based Detection Engine (Mini Snort)
* Web-Based Monitoring Dashboard
* Email Notifications
* Machine Learning-Based Threat Detection
* Automatic IP Blocking and Response Mechanisms

## Conclusion

This project successfully demonstrates the implementation of a basic Intrusion Detection System using Python and Scapy. The system is capable of monitoring live network traffic, analyzing packets, and detecting common attacks such as Port Scanning, SYN Floods, ICMP Floods, and SQL Injection attempts.

The project provided practical experience in packet analysis, network security monitoring, and attack detection techniques. It serves as a strong foundation for building more advanced intrusion detection and network security solutions in the future.
