#!/usr/bin/env python3
"""
Fast TCP Port Scanner with Threading
A multi-threaded port scanner that checks for open TCP ports on a target host.
"""

# Import necessary modules
from socket import *
import sys
import argparse
import threading      # ← NEW: For running multiple scans at once
import queue          # ← NEW: For managing ports to scan
import time           # ← NEW: For tracking scan duration

# Define a function that attempts to connect to a single port on a target host
# Parameters: tgtHost = IP address or hostname, tgtPort = port number to check
def conScan(tgtHost, tgtPort):
    """
    Attempts to connect to a specific port on a target host.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPort (int): The port number to scan
    
    Returns:
        bool: True if port is open, False if closed
    """
    # Try-except block to handle any connection errors gracefully
    try:
        # Create a new socket object
        # AF_INET = IPv4 address family (use IPv4)
        # SOCK_STREAM = TCP protocol (reliable, connection-oriented)
        connskt = socket(AF_INET, SOCK_STREAM)
        
        # Set a timeout for this specific socket
        connskt.settimeout(1)
        
        # Attempt to establish a TCP connection to the target host and port
        # connect() will raise an exception if it fails (e.g., port closed, host unreachable)
        connskt.connect((tgtHost, tgtPort))
        
        # If connection succeeds, print that the port is open
        # The plus sign (+) indicates an open port in the output
        print('[+] %d/tcp open' % tgtPort)
        
        # Close the socket connection to free up system resources
        # Important to prevent resource leaks and keep connections clean
        connskt.close()
        return True
    
    # If ANY exception occurs during the connection attempt (timeout, refused, etc.)
    except:
        # Print that the port is closed (or unreachable) - but only in verbose mode
        # The minus sign (-) indicates the port is not accessible
        # We don't print closed ports to keep output clean
        return False

# NEW: Worker function for threading
def worker(tgtHost, port_queue, results):
    """
    Worker thread function that takes ports from the queue and scans them.
    
    Args:
        tgtHost (str): The target hostname or IP address
        port_queue (Queue): Queue containing ports to scan
        results (list): List to store results (open ports)
    """
    # Keep running until the queue is empty
    while not port_queue.empty():
        # Get a port from the queue
        port = port_queue.get()
        
        # Scan the port
        if conScan(tgtHost, port):
            # If port is open, add to results
            results.append(port)
        
        # Mark this task as done in the queue
        port_queue.task_done()

# Define the main port scanning function with threading
# Parameters: tgtHost = target hostname or IP, tgtPorts = list of ports to scan
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
    # This converts something like 'google.com' to '142.250.185.78'
    try:
        tgtIP = gethostbyname(tgtHost)
    # If hostname resolution fails (e.g., host doesn't exist, DNS issues)
    except:
        # Print an error message indicating the host couldn't be resolved
        print('[-] Cannot Resolve %s ' % tgtHost)
        # Return from the function early (stop execution)
        # No point continuing if we can't find the host
        return []
    
    # Now try to perform a reverse DNS lookup
    # This attempts to find the hostname from the IP address
    try:
        # gethostbyaddr() returns a tuple: (hostname, aliases, IP addresses)
        tgtName = gethostbyaddr(tgtIP)
        # If successful, print the resolved hostname as the scan target
        # This often shows the canonical name or the original hostname
        print('\n[+] Scan Result of: %s (%s)' % (tgtName[0], tgtIP))
    
    # If reverse DNS lookup fails (common for many IPs)
    except:
        # Print just the IP address since we couldn't find a hostname
        print('\n[+] Scan Result of: %s' % tgtIP)
    
    # NEW: Start timing the scan
    start_time = time.time()
    
    # NEW: Create a queue and fill it with ports
    port_queue = queue.Queue()
    for port in tgtPorts:
        port_queue.put(port)
    
    # NEW: List to store open ports
    results = []
    
    # NEW: Create and start worker threads
    threads = []
    for _ in range(num_threads):
        # Create a thread
        t = threading.Thread(target=worker, args=(tgtHost, port_queue, results))
        t.start()
        threads.append(t)
    
    # NEW: Wait for all threads to complete
    for t in threads:
        t.join()
    
    # NEW: Calculate scan duration
    duration = time.time() - start_time
    
    # NEW: Print summary
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
        description='Multi-threaded TCP Port Scanner',
        epilog='Example: python PORT_SCANNER_V2.0.py google.com 80,443,22'
    )
    
    # Add the target host argument
    parser.add_argument(
        'target',
        help='Target hostname or IP address to scan'
    )
    
    # Add the ports argument
    parser.add_argument(
        'ports',
        help='Comma-separated list of ports to scan (e.g., 80,443,22)'
    )
    
    # NEW: Add optional threads argument
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of threads to use (default: 10)'
    )
    
    # NEW: Add verbose mode
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all ports (including closed ones)'
    )
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Convert the ports string to a list of integers
    try:
        # Split the comma-separated string, convert each to int
        port_list = [int(p.strip()) for p in args.ports.split(',')]
        
        # Validate port numbers (between 1 and 65535)
        for port in port_list:
            if port < 1 or port > 65535:
                print(f'[-] Invalid port number: {port}. Ports must be between 1 and 65535')
                return
        
    except ValueError:
        # If conversion fails, show an error
        print('[-] Invalid port format. Please use comma-separated numbers (e.g., 80,443,22)')
        return
    
    # NEW: Validate thread count
    if args.threads < 1:
        print('[-] Thread count must be at least 1')
        return
    if args.threads > 100:
        print('[-] Thread count too high. Max is 100')
        return
    
    # NEW: Print scan configuration
    print('[+] Starting scan...')
    print('[+] Target: %s' % args.target)
    print('[+] Ports: %s' % args.ports)
    print('[+] Threads: %d' % args.threads)
    print('[+] Verbose: %s' % ('Yes' if args.verbose else 'No'))
    print('-' * 40)
    
    # Call the portScan function with the provided arguments
    portScan(args.target, port_list, args.threads)

# This is the entry point of the script
# The code inside this if block only runs when the script is executed directly
# (not when it's imported as a module by another script)
if __name__ == '__main__':
    main()