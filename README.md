# Network-Threat-Detection-and-Prevention-with-Suricata-and-Wazuh

This project documents the design, setup, and testing of a network-based threat detection and prevention lab using Suricata IDS/IPS, Wazuh SIEM, and Open AppSec WAF. The objective is to simulate real-world threats and verify the detection and prevention mechanism

## Project Overview
The goal of this lab is to build a modular network security environment, where:

- Suricata monitors and blocks malicious traffic at the network layer (IDS/IPS)
- Open AppSec provides WAF protection for web applications
- Wazuh aggregates logs and detects incidents

The lab replicates SOC-level visibility and allows testing against simulated attacks from Kali Linux.

## 🔍 Project Goals  

- Deploy Suricata as an IPS gateway
- Route all DMZ traffic through Suricata
- Enable Suricata log forwarding to Wazuh
- Protect the web server using Open AppSec WAF
- Test custom Suricata rules (detection + blocking)
- Simulate real attacks from Kali Linux and verify detection/prevention

📷 **Lab Diagrame** 

![Diagrame](images/diagrame.png) 
  
## 🧪 Tools and Technologies

| Component         | Role                                   |
| ----------------- | -------------------------------------- |
| Debian 12         | Used for Suricata Gateway              |
| Suricata          | IDS/IPS engine                         |
| IPTables          | Routing & NFQUEUE integration          |
| OWASP Juice Shop  | Web application in DMZ                 |
| Open AppSec (WAF) | Web app firewall protecting Juice Shop |
| Wazuh Server      | Log aggregation & alerting             |
| Kali Linux        | Attacker VM                            |
| Metasploitable2   | Additional vulnerable services in DMZ  |

## 🧩 Key Steps

### 1. Lab VM Setup
- 3 Virtual Machines (Debian x3):
  - Suricata Gateway (2 NICs)
  - Web Server ([Juice Shop](https://github.com/juice-shop/juice-shop) + Open AppSec)
  - Vulnerable Host ([Metasploitable 2](https://sourceforge.net/projects/metasploitable/))
- 1 Kali Linux VM for attack simulation
- 1 Wazuh server (already set up [here](https://github.com/Apelsyn582/Wazuh-SIEM-Home-Lab-Detection-of-Suspicious-Activities/edit/main/README.md#1-wazuh-server-setup))

### 2. IPTables and Network Routing
- Debian Suricata machine set up as gateway with 2 NICs:
  - enp0s3 — WAN (LAN side)
  - enp0s8 — DMZ interface
- Configured IP forwarding and NAT
- Configured iptables to forward DMZ traffic

📄[View the Report here](https://github.com/Apelsyn582/Network-Threat-Detection-and-Prevention-with-Suricata-and-Wazuh/blob/main/Full%20Step-by-Step%20Instruction%20for%20step%202.pdf)

### 3. Suricata Installation and Configuration
Installed Suricata in IPS mode (NFQUEUE)

Set custom rules:
- Port scan detection
- OS fingerprinting detection
- Service version scan
- SQLi or XSS payloads

📷 /etc/suricata/suricata.yaml
📷 EVE JSON logs
📷 Suricata blocking traffic in real-time

### 4. Wazuh Integration
- Installed Wazuh agent on Suricata Gateway
- Configured log forwarding of /var/log/suricata/eve.json
- Confirmed real-time alerts in Wazuh dashboard

📷 Wazuh alert
📷 Agent status
📷 Event with tag suricata.alert

### 5. Web Server and WAF (Open AppSec)

- Installed Juice Shop via Docker or Node.js
- Integrated Open AppSec (Docker or native)
- Enabled protections (SQLi, RCE, XXE, etc.)
- Tuned WAF logging

📷 Juice Shop running
📷 WAF dashboard / log entries
📷 Blocked attack by WAF

### 6. Attack Simulation from Kali
Ran:
- Nmap scans
- Nikto/Dirb
- SQLMap
- Metasploit module or exploit
- Verified detections in:
- Suricata logs
- Wazuh dashboard

WAF logs

📷 Terminal output of attack
📷 Blocked alert in Wazuh
📷 Suricata JSON log (with rule match)
📷 AppSec WAF log (if triggered)

### 7. Analysis & Conclusion
-Attack vector vs detection correlation
-Prevention efficiency of Suricata vs WAF
-Wazuh's role in visibility & triage
-Possible next steps (add Honeypots, ELK, etc.)

📷 Summary Table of Detected Attacks
