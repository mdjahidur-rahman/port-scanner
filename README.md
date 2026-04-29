# 🔍 Python Port Scanner

A simple yet powerful Python-based port scanner built using socket programming and multi-threading.

## 🚀 Features
- Single port scanning
- Port range scanning
- Multi-threaded scanning for performance
- Service detection using common ports
- Basic banner grabbing (HTTP/SSH/FTP)
- Scan time measurement

## 🛠️ Technologies Used
- Python 3
- socket programming
- threading
- concurrent.futures

## ▶️ How to Run
```bash
python port_scanner.py

## ⚙️ How It Works

1. User enters a target (IP or domain)
2. User selects port or port range
3. Scanner creates TCP socket connections
4. Each port is tested using `connect_ex()`
5. If connection succeeds → port is OPEN
6. If connection fails → port is CLOSED
7. For open ports, optional banner grabbing is performed
8. Results are displayed with scan summary


## 🖥️ Example Output 1

### Single Port Scan

Enter target (IP or domain): google.com
Enter port: 80

[+] Port 80 (HTTP) OPEN → Server: gws

Scan completed in 0.42 seconds


Enter target: google.com
Enter start port: 20
Enter end port: 100

[+] Port 22 (SSH) is OPEN
[+] Port 80 (HTTP) OPEN → Server: gws
[-] Port 23 (Telnet) is CLOSED
...

--- Scan Summary ---
Total ports scanned: 81
Open ports: 2
Closed ports: 79
Errors: 0


## 🖥️ Example Output 2

### Range Port Scan

Enter target: google.com
Enter start port: 20
Enter end port: 100

[+] Port 22 (SSH) is OPEN
[+] Port 80 (HTTP) OPEN → Server: gws
[-] Port 23 (Telnet) is CLOSED
...

--- Scan Summary ---
Total ports scanned: 81
Open ports: 2
Closed ports: 79
Errors: 0

Scan completed in 1.12 seconds


## 🧠 Skills Learned

- Python socket programming
- TCP/IP connection behavior
- Port scanning fundamentals
- Multi-threading and concurrency
- Race conditions and thread safety (locks)
- Network service identification
- Basic banner grabbing techniques
- Error handling in network applications



## 🚀 Future Improvements

- Add thread pool optimization (limit max threads)
- Improve banner grabbing with protocol-specific handlers (HTTP/SSH/FTP)
- Save scan results to file (JSON / CSV report)
- Add progress bar for large scans
- Add CLI arguments support (argparse)
- Detect service versions more accurately (fingerprinting)
- Add GUI version of the scanner