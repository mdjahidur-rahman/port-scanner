import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


class PortScanner:
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy"
    }

    UDP_COMMON_PORTS = {
        53: "DNS",
        67: "DHCP",
        69: "TFTP",
        123: "NTP",
        161: "SNMP",
        162: "SNMP-Trap",
        514: "Syslog",
        520: "RIP"
    }

    def __init__(self, timeout=1):
        self.timeout = timeout

    # Core Scanner
    def scan_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((target, port))
            sock.close()

            return result

        except socket.gaierror:
            print("[!] Hostname could not be resolved")
            return None

        except socket.error:
            print("[!] Could not connect to server")
            return None
        
    def grab_banner(self, target, port):
        try: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            sock.connect((target, port))

            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % target.encode())

            banner = sock.recv(1024).decode(errors='ignore')
            for line in banner.split("\n"):
                if "Server:" in line:
                    return line.strip()
            sock.close()
            return banner if banner else None
        
        except:
            return None

    # Validation
    def validate_target(self, target):
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            print("[!] Invalid hostname")
            return False

    def validate_port_range(self, start_port, end_port):
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print("[!] Invalid port range (must be 1–65535 and start <= end)")
            return False
        return True

    # Scan Modes
    def scan_single(self):
        target = input("Enter target (IP or domain): ")

        if not self.validate_target(target):
            return

        try:
            port = int(input("Enter port: "))
        except ValueError:
            print("[!] Invalid port input")
            return

        service = self.COMMON_PORTS.get(port, "Unknown")
        start_time = time.time()
        result = self.scan_port(target, port)
        elapsed = time.time() - start_time

        if result == 0:
            banner = self.grab_banner(target, port)
            if banner:
                line = f"[+] Port {port} ({service}) OPEN → {banner}"
            else:
                line = f"[+] Port {port} ({service}) is OPEN"
            stats = {"open": 1, "closed": 0, "error": 0, "total": 1}
        elif result is None:
            line = f"[!] Error scanning port {port}"
            stats = {"open": 0, "closed": 0, "error": 1, "total": 1}
        else:
            line = f"[-] Port {port} ({service}) is CLOSED"
            stats = {"open": 0, "closed": 1, "error": 0, "total": 1}

        print(line)
        self.save_results([line], target, "TCP Single", stats, elapsed)

    def scan_range(self):
        target = input("Enter target (IP or domain): ")

        if not self.validate_target(target):
            return

        try:
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
        except ValueError:
            print("[!] Invalid input")
            return

        if not self.validate_port_range(start_port, end_port):
            return

        open_ports = 0
        closed_ports = 0
        error_ports = 0
        output = []

        start_time = time.time()

        for port in range(start_port, end_port + 1):
            result = self.scan_port(target, port)
            service = self.COMMON_PORTS.get(port, "Unknown")

            if result == 0:
                banner = self.grab_banner(target, port)
                if banner:
                    line = f"[+] Port {port} ({service}) OPEN → {banner}"
                else:
                    line = f"[+] Port {port} ({service}) is OPEN"
                open_ports += 1

            elif result is None:
                line = f"[!] Error scanning port {port}"
                error_ports += 1

            else:
                line = f"[-] Port {port} ({service}) is CLOSED"
                closed_ports += 1

            print(line)
            output.append(line)

        end_time = time.time()
        elapsed = end_time - start_time

        self.report_summary(start_port, end_port, open_ports, closed_ports, error_ports)
        print(f"\nScan completed in {elapsed:.2f} seconds")

        stats = {"open": open_ports, "closed": closed_ports, "error": error_ports,
                 "total": end_port - start_port + 1}
        self.save_results(output, target, "TCP Range", stats, elapsed)


    def scan_worker(self, target, port, results, output, lock):
        result = self.scan_port(target, port)
        service = self.COMMON_PORTS.get(port, "Unknown")

        if result == 0:
            banner = self.grab_banner(target, port)
            if banner:
                output.append(f"[+] Port {port} ({service}) OPEN → {banner}")
            else:
                output.append(f"[+] Port {port} ({service}) OPEN")
            with lock:
                results["open"] += 1

        elif result is None:
            output.append(f"[!] Error scanning port {port}")
            with lock:
                results["error"] += 1

        else:
            output.append(f"[-] Port {port} ({service}) is CLOSED")
            with lock:
                results["closed"] += 1

    def scan_range_thread(self):
        target = input("Enter target (IP or domain): ")

        if not self.validate_target(target):
            return

        try:
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
        except ValueError:
            print("[!] Invalid input")
            return

        if not self.validate_port_range(start_port, end_port):
            return
        
        lock = threading.Lock()
        results = {"open": 0, "closed": 0, "error": 0}
        output = []

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=5) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(self.scan_worker, target, port, results, output, lock)

        end_time = time.time()
        elapsed = end_time - start_time

        for line in sorted(output):
            print(line)

        self.report_summary(start_port, end_port,
                            results["open"],
                            results["closed"],
                            results["error"])

        print(f"\nScan completed in {elapsed:.2f} seconds with Threading")

        stats = {"open": results["open"], "closed": results["closed"],
                 "error": results["error"], "total": end_port - start_port + 1}
        self.save_results(sorted(output), target, "TCP Range (Threaded)", stats, elapsed)



    # UDP Scan
    def scan_udp_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"", (target, port))
            sock.recvfrom(1024)
            sock.close()
            return "open"
        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
        except socket.error:
            return "closed"

    def scan_udp_range(self):
        target = input("Enter target (IP or domain): ")

        if not self.validate_target(target):
            return

        try:
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
        except ValueError:
            print("[!] Invalid input")
            return

        if not self.validate_port_range(start_port, end_port):
            return

        open_ports = 0
        open_filtered_ports = 0
        closed_ports = 0
        output = []

        start_time = time.time()

        for port in range(start_port, end_port + 1):
            status = self.scan_udp_port(target, port)
            service = self.UDP_COMMON_PORTS.get(port, "Unknown")

            if status == "open":
                line = f"[+] Port {port}/UDP ({service}) OPEN"
                open_ports += 1
            elif status == "open|filtered":
                line = f"[~] Port {port}/UDP ({service}) OPEN|FILTERED"
                open_filtered_ports += 1
            else:
                line = f"[-] Port {port}/UDP ({service}) CLOSED"
                closed_ports += 1

            print(line)
            output.append(line)

        end_time = time.time()
        elapsed = end_time - start_time

        print("\n--- UDP Scan Summary ---")
        print(f"Total ports scanned: {end_port - start_port + 1}")
        print(f"Open: {open_ports}")
        print(f"Open|Filtered: {open_filtered_ports}")
        print(f"Closed: {closed_ports}")
        print(f"\nScan completed in {elapsed:.2f} seconds")

        stats = {"open": open_ports, "open_filtered": open_filtered_ports,
                 "closed": closed_ports, "error": 0,
                 "total": end_port - start_port + 1}
        self.save_results(output, target, "UDP Range", stats, elapsed)

    # Save Results
    def save_results(self, output_lines, target, scan_type, stats, elapsed):
        choice = input("\nSave results to file? (y/n): ").strip().lower()
        if choice != "y":
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace(":", "_")
        filename = f"scan_{safe_target}_{timestamp}.txt"

        with open(filename, "w") as f:
            f.write("Port Scan Results\n")
            f.write("=================\n")
            f.write(f"Target   : {target}\n")
            f.write(f"Scan type: {scan_type}\n")
            f.write(f"Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 40 + "\n")
            for line in output_lines:
                f.write(line + "\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total ports scanned: {stats['total']}\n")
            if "open_filtered" in stats:
                f.write(f"Open: {stats['open']} | Open|Filtered: {stats['open_filtered']} | "
                        f"Closed: {stats['closed']}\n")
            else:
                f.write(f"Open: {stats['open']} | Closed: {stats['closed']} | "
                        f"Errors: {stats['error']}\n")
            f.write(f"Elapsed: {elapsed:.2f} seconds\n")

        print(f"[+] Results saved to {filename}")

    # Reporting
    def report_summary(self, start, end, open_ports, closed_ports, error_ports):
        total_ports = end - start + 1

        print("\n--- Scan Summary ---")
        print(f"Total ports scanned: {total_ports}")
        print(f"Open ports: {open_ports}")
        print(f"Closed ports: {closed_ports}")
        print(f"Errors: {error_ports}")

    # Menu
    def run(self):
        while True:
            print("\n===== PORT SCANNER =====")
            print("1. Scan single port")
            print("2. Scan port range")
            print("3. Scan port range (Threading)")
            print("4. Scan UDP port range")
            print("5. Exit")

            choice = input("Select option: ")

            if choice == "1":
                self.scan_single()
            elif choice == "2":
                self.scan_range()
            elif choice == "3":
                self.scan_range_thread()
            elif choice == "4":
                self.scan_udp_range()
            elif choice == "5":
                print("Exiting...")
                break
            else:
                print("[!] Invalid choice")


# Entry Point
if __name__ == "__main__":
    scanner = PortScanner()
    scanner.run()