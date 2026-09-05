#!/usr/bin/env python3
"""
Fast TCP Port Scanner with Threading and Port Ranges
A multi-threaded port scanner that supports single ports, ranges, and mixed formats.
"""

# Import necessary modules
from socket import *
import sys
import argparse
import threading
import queue
import time
import re          # ← NEW: For parsing port ranges

# Define a function that attempts to connect to a single port on a target host
def conScan(tgtHost, tgtPort):
    """
    Attempts to connect to a specific port on a target host.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPort (int): The port number to scan
    
    Returns:
        bool: True if port is open, False if closed
    """
    try:
        connskt = socket(AF_INET, SOCK_STREAM)
        connskt.settimeout(1)
        connskt.connect((tgtHost, tgtPort))
        print('[+] %d/tcp open' % tgtPort)
        connskt.close()
        return True
    except:
        return False

# NEW: Function to parse port specifications
def parse_ports(port_spec):
    """
    Parse port specifications that can include:
    - Single ports: 80,443,22
    - Port ranges: 1-1000
    - Mixed: 80,443,22,1000-2000,8080
    
    Args:
        port_spec (str): The port specification string
    
    Returns:
        list: List of port numbers
    """
    ports = []
    
    # Split by comma to handle multiple entries
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()  # Remove whitespace
        
        # Check if this is a range (contains '-')
        if '-' in part:
            try:
                # Split the range
                start_str, end_str = part.split('-')
                start = int(start_str.strip())
                end = int(end_str.strip())
                
                # Validate range
                if start < 1 or end > 65535 or start > end:
                    print(f'[-] Invalid port range: {part}. Must be between 1-65535 and start <= end')
                    continue
                
                # Add all ports in the range
                for port in range(start, end + 1):
                    ports.append(port)
                    
            except ValueError:
                print(f'[-] Invalid port range format: {part}. Use start-end (e.g., 1-1000)')
                continue
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    print(f'[-] Invalid port number: {port}. Must be between 1 and 65535')
                    continue
                ports.append(port)
            except ValueError:
                print(f'[-] Invalid port format: {part}. Use numbers or ranges like 1-1000')
                continue
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ports = []
    for port in ports:
        if port not in seen:
            seen.add(port)
            unique_ports.append(port)
    
    return unique_ports

# NEW: Worker function for threading (unchanged but using updated conScan)
def worker(tgtHost, port_queue, results):
    """
    Worker thread function that takes ports from the queue and scans them.
    """
    while not port_queue.empty():
        port = port_queue.get()
        if conScan(tgtHost, port):
            results.append(port)
        port_queue.task_done()

# Define the main port scanning function with threading
def portScan(tgtHost, tgtPorts, num_threads=10):
    """
    Performs a multi-threaded port scan on a target host.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPorts (list): A list of port numbers to scan
        num_threads (int): Number of threads to use (default: 10)
    
    Returns:
        list: List of open ports
    """
    # First, try to resolve the hostname to an IP address
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print('[-] Cannot Resolve %s ' % tgtHost)
        return []
    
    # Now try to perform a reverse DNS lookup
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Result of: %s (%s)' % (tgtName[0], tgtIP))
    except:
        print('\n[+] Scan Result of: %s' % tgtIP)
    
    # NEW: Show how many ports will be scanned
    print('[+] Total ports to scan: %d' % len(tgtPorts))
    
    # Start timing the scan
    start_time = time.time()
    
    # Create a queue and fill it with ports
    port_queue = queue.Queue()
    for port in tgtPorts:
        port_queue.put(port)
    
    # List to store open ports
    results = []
    
    # Create and start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(tgtHost, port_queue, results))
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Calculate scan duration
    duration = time.time() - start_time
    
    # Print summary
    print('\n[+] Scan completed in %.2f seconds' % duration)
    print('[+] Found %d open ports' % len(results))
    if results:
        print('[+] Open ports: %s' % ', '.join(str(p) for p in sorted(results)))
    
    return results

# Define the main function that parses command-line arguments
def main():
    """
    Main function that handles command-line arguments and initiates the scan.
    """
    # Create an argument parser with a description
    parser = argparse.ArgumentParser(
        description='Multi-threaded TCP Port Scanner with Port Ranges',
        epilog='Example: python PORT_SCANNER_V2.1.py google.com 80,443,22,1000-2000'
    )
    
    # Add the target host argument
    parser.add_argument(
        'target',
        help='Target hostname or IP address to scan'
    )
    
    # Add the ports argument (NOW SUPPORTS RANGES!)
    parser.add_argument(
        'ports',
        help='Ports to scan. Examples: 80,443,22 OR 1-1000 OR 80,443,1000-2000,8080'
    )
    
    # Add optional threads argument
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of threads to use (default: 10)'
    )
    
    # Add verbose mode
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all ports (including closed ones)'
    )
    
    # Parse the arguments
    args = parser.parse_args()
    
    # NEW: Parse ports with range support
    port_list = parse_ports(args.ports)
    
    # Validate that we have ports to scan
    if not port_list:
        print('[-] No valid ports specified')
        return
    
    # Validate thread count
    if args.threads < 1:
        print('[-] Thread count must be at least 1')
        return
    if args.threads > 100:
        print('[-] Thread count too high. Max is 100')
        return
    
    # Print scan configuration
    print('[+] Starting scan...')
    print('[+] Target: %s' % args.target)
    print('[+] Ports: %s' % args.ports)
    print('[+] Total ports: %d' % len(port_list))
    print('[+] Threads: %d' % args.threads)
    print('[+] Verbose: %s' % ('Yes' if args.verbose else 'No'))
    print('-' * 40)
    
    # Call the portScan function with the provided arguments
    portScan(args.target, port_list, args.threads)

if __name__ == '__main__':
    main()