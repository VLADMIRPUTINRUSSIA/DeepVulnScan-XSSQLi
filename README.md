# DeepVulnScan-XSSQLi

**DeepVulnScan-XSSQLi** is a high-performance, terminal-based vulnerability scanner for identifying XSS and SQL Injection vulnerabilities.  
It includes a full set of modern payloads, logging, Discord webhook alerting, and supports advanced deep scanning on any target, method, or port.

---

## Project Metadata
- Author: VLADMIRPUTINRUSSIA
- Name: DeepVulnScan-XSSQLi
- Version: 1.0.0
- Status: Active
- Created on:  
  - ISO 8601 UTC (Zulu): 2025-07-23T20:45:00Z  
  - GMT (UTC+0): 2025-07-23T20:45:00+00:00  
  - CEST (UTC+2): 2025-07-23T22:45:00+02:00

---

## Features

- Full injection detection for Reflected and Blind SQL Injection
- Extensive detection of Reflected, Stored, and DOM-based XSS
- Payload engine supporting 200+ real-world tested vectors
- Discord webhook alert system with ISO 8601 log metadata
- CSV logging system for forensic review
- Deep scanning through GET, POST, and custom HTTP methods
- Optional port and header customization
- Works on Debian, Ubuntu, Kali, Parrot OS
- Compatible with headless use (no GUI dependencies)

---

## Installation

```bash
git clone [https://github.com/VLADMIRPUTINRUSSIA/DeepVulnScan-XSSQLi.git]
cd deepvulnscan-xssqli
pip3 install -r requirements.txt
chmod +x xss_sqli_scanner.py
./xss_sqli_scanner.py
