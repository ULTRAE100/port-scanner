#!/usr/bin/env python3
"""
Advanced TCP Port Scanner with Banner Grabbing
A multi-threaded port scanner that identifies services by grabbing banners.
"""

# Import necessary modules
from socket import *
import sys
import argparse
import threading
import queue
import time
import re

# Dictionary of common services and their default ports
SERVICE_MAP = {
    20: 'FTP-data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPCbind',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

def grab_banner(tgtHost, tgtPort, timeout=3):
    """
    Attempts to grab a banner from a service on the specified port.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPort (int): The port number to connect to
        timeout (int): Timeout in seconds
    
    Returns:
        str: The banner/response or None if failed
    """
    try:
        # Create a socket
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect to the target
        sock.connect((tgtHost, tgtPort))
        
        # Send a probe based on common services
        probe = get_probe(tgtPort)
        if probe:
            sock.send(probe.encode())
        
        # Receive the banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        # Clean up the banner
        banner = banner.replace('\r', '').replace('\n', ' ').strip()
        banner = ' '.join(banner.split())  # Remove extra spaces
        
        sock.close()
        
        if banner:
            return banner
        return None
        
    except:
        return None

def get_probe(port):
    """
    Returns a probe string based on the port number.
    
    Args:
        port (int): The port number
    
    Returns:
        str: Probe string or None
    """
    # HTTP/HTTPS probes
    if port in [80, 8080, 8000, 8008]:
        return 'HEAD / HTTP/1.0\r\n\r\n'
    elif port in [443, 8443]:
        return 'HEAD / HTTP/1.0\r\n\r\n'
    # SMTP probe
    elif port == 25:
        return 'EHLO example.com\r\n'
    # POP3 probe
    elif port == 110:
        return 'CAPA\r\n'
    # IMAP probe
    elif port == 143:
        return 'A001 CAPABILITY\r\n'
    # FTP probe
    elif port == 21:
        return 'FEAT\r\n'
    # SSH probe
    elif port == 22:
        return ''  # SSH usually responds without a probe
    # MySQL probe
    elif port == 3306:
        return ''  # MySQL responds to connection
    # PostgreSQL probe
    elif port == 5432:
        return ''  # PostgreSQL responds to connection
    # Redis probe
    elif port == 6379:
        return 'PING\r\n'
    # Memcached probe
    elif port == 11211:
        return 'version\r\n'
    # RDP probe
    elif port == 3389:
        return ''  # RDP responds to connection
    else:
        return None

def identify_service(port, banner):
    """
    Identifies the service based on port and banner.
    
    Args:
        port (int): The port number
        banner (str): The banner text
    
    Returns:
        str: Service name and version
    """
    # Default service from port map
    service = SERVICE_MAP.get(port, 'Unknown')
    
    if not banner:
        return service
    
    # HTTP/HTTPS detection
    if port in [80, 443, 8080, 8443]:
        if 'Server:' in banner or 'server:' in banner.lower():
            match = re.search(r'(?:Server:|server:)\s*([^\s]+)', banner)
            if match:
                return f'HTTP ({match.group(1)})'
        return service
    
    # SSH detection
    if port == 22:
        if 'SSH' in banner.upper():
            match = re.search(r'SSH-([\d.]+)', banner)
            if match:
                return f'SSH (OpenSSH {match.group(1)})'
            return f'SSH ({banner[:50]})'
        return 'SSH'
    
    # FTP detection
    if port == 21:
        if 'FTP' in banner.upper():
            match = re.search(r'([\w\s]+FTP[\w\s]+)', banner, re.IGNORECASE)
            if match:
                return f'FTP ({match.group(1)[:50]})'
            return f'FTP ({banner[:50]})'
        return 'FTP'
    
    # SMTP detection
    if port == 25:
        if 'SMTP' in banner.upper() or 'ESMTP' in banner.upper():
            match = re.search(r'([\w\s]+SMTP[\w\s]+)', banner, re.IGNORECASE)
            if match:
                return f'SMTP ({match.group(1)[:50]})'
            return f'SMTP ({banner[:50]})'
        return 'SMTP'
    
    # MySQL detection
    if port == 3306:
        if 'mysql' in banner.lower():
            match = re.search(r'mysql[\s]+([\d.]+)', banner.lower())
            if match:
                return f'MySQL ({match.group(1)})'
            return 'MySQL'
        return 'MySQL'
    
    # Redis detection
    if port == 6379:
        if 'PONG' in banner.upper():
            match = re.search(r'PONG', banner)
            if match:
                return 'Redis'
            return 'Redis'
        return 'Redis'
    
    # Banner contains service info
    if banner:
        # Check for common keywords
        if 'Apache' in banner:
            return f'HTTP ({banner[:50]})'
        elif 'nginx' in banner.lower():
            return f'HTTP ({banner[:50]})'
        elif 'Microsoft' in banner:
            return f'HTTP ({banner[:50]})'
        elif 'OpenSSH' in banner:
            return f'SSH ({banner[:50]})'
        elif 'vsftpd' in banner.lower():
            return f'FTP ({banner[:50]})'
        elif 'ProFTPD' in banner:
            return f'FTP ({banner[:50]})'
        else:
            return f'{service} ({banner[:50]})'
    
    return service

def conScan(tgtHost, tgtPort, verbose=False):
    """
    Attempts to connect to a specific port on a target host and grab banner.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPort (int): The port number to scan
        verbose (bool): Whether to show all output
    
    Returns:
        dict: Port status and banner information
    """
    result = {
        'port': tgtPort,
        'open': False,
        'banner': None,
        'service': None,
        'banner_grabbed': False
    }
    
    try:
        connskt = socket(AF_INET, SOCK_STREAM)
        connskt.settimeout(2)
        connskt.connect((tgtHost, tgtPort))
        result['open'] = True
        
        # Try to grab banner
        banner = grab_banner(tgtHost, tgtPort)
        if banner:
            result['banner'] = banner
            result['banner_grabbed'] = True
            result['service'] = identify_service(tgtPort, banner)
        
        # If no banner grabbed, identify service by port only
        if not result['service']:
            result['service'] = SERVICE_MAP.get(tgtPort, 'Unknown')
        
        # Print result
        if verbose or result['open']:
            if result['banner_grabbed']:
                print(f'[+] {tgtPort}/tcp open  - {result["service"]}')
            else:
                print(f'[+] {tgtPort}/tcp open  - {result["service"]}')
        
        connskt.close()
        
    except:
        if verbose:
            print(f'[-] {tgtPort}/tcp closed')
    
    return result

def worker(tgtHost, port_queue, results, verbose=False):
    """
    Worker thread function that takes ports from the queue and scans them.
    """
    while not port_queue.empty():
        port = port_queue.get()
        result = conScan(tgtHost, port, verbose)
        if result['open']:
            results.append(result)
        port_queue.task_done()

def portScan(tgtHost, tgtPorts, num_threads=10, verbose=False):
    """
    Performs a multi-threaded port scan with banner grabbing.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPorts (list): A list of port numbers to scan
        num_threads (int): Number of threads to use
        verbose (bool): Whether to show all output
    
    Returns:
        list: Results for open ports
    """
    # Resolve hostname
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print('[-] Cannot Resolve %s ' % tgtHost)
        return []
    
    # Reverse DNS lookup
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Result of: %s (%s)' % (tgtName[0], tgtIP))
    except:
        print('\n[+] Scan Result of: %s' % tgtIP)
    
    print('[+] Total ports to scan: %d' % len(tgtPorts))
    print('[+] Performing banner grabbing on open ports...\n')
    
    # Start timing
    start_time = time.time()
    
    # Create queue
    port_queue = queue.Queue()
    for port in tgtPorts:
        port_queue.put(port)
    
    # Results list
    results = []
    
    # Create and start threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(tgtHost, port_queue, results, verbose))
        t.start()
        threads.append(t)
    
    # Wait for all threads
    for t in threads:
        t.join()
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Print summary
    print('\n' + '=' * 50)
    print('[+] Scan completed in %.2f seconds' % duration)
    print('[+] Found %d open ports' % len(results))
    
    if results:
        print('\n[+] Open Ports with Service Information:')
        print('-' * 50)
        for result in sorted(results, key=lambda x: x['port']):
            service_info = result.get('service', 'Unknown')
            port_str = f"  {result['port']}/tcp"
            print(f'{port_str:<12} {service_info}')
            if result.get('banner_grabbed') and result.get('banner'):
                banner_preview = result['banner'][:100] + '...' if len(result['banner']) > 100 else result['banner']
                print(f'    Banner: {banner_preview}')
                print()
    
    return results

# Parse ports function (from v2.1)
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
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        
        if '-' in part:
            try:
                start_str, end_str = part.split('-')
                start = int(start_str.strip())
                end = int(end_str.strip())
                
                if start < 1 or end > 65535 or start > end:
                    print(f'[-] Invalid port range: {part}')
                    continue
                
                for port in range(start, end + 1):
                    ports.append(port)
                    
            except ValueError:
                print(f'[-] Invalid port range format: {part}')
                continue
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    print(f'[-] Invalid port number: {port}')
                    continue
                ports.append(port)
            except ValueError:
                print(f'[-] Invalid port format: {part}')
                continue
    
    # Remove duplicates
    seen = set()
    unique_ports = []
    for port in ports:
        if port not in seen:
            seen.add(port)
            unique_ports.append(port)
    
    return unique_ports

def main():
    """
    Main function that handles command-line arguments and initiates the scan.
    """
    parser = argparse.ArgumentParser(
        description='Advanced TCP Port Scanner with Banner Grabbing',
        epilog='Example: python port_scanner_v3.0.py google.com 80,443,22'
    )
    
    parser.add_argument(
        'target',
        help='Target hostname or IP address to scan'
    )
    
    parser.add_argument(
        'ports',
        help='Ports to scan. Examples: 80,443,22 OR 1-1000 OR 80,443,1000-2000,8080'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of threads to use (default: 10)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all ports (including closed ones)'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner grabbing (faster scan)'
    )
    
    args = parser.parse_args()
    
    # Parse ports
    port_list = parse_ports(args.ports)
    
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
    
    # Print configuration
    print('[+] Starting advanced scan...')
    print('[+] Target: %s' % args.target)
    print('[+] Ports: %s' % args.ports)
    print('[+] Total ports: %d' % len(port_list))
    print('[+] Threads: %d' % args.threads)
    print('[+] Banner Grabbing: %s' % ('Disabled' if args.no_banner else 'Enabled'))
    print('=' * 50)
    
    # Call portScan
    portScan(args.target, port_list, args.threads, args.verbose)

if __name__ == '__main__':
    main()