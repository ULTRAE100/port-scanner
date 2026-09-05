#!/usr/bin/env python3
"""
Simple TCP Port Scanner
A lightweight port scanner that checks for open TCP ports on a target host.
"""

# Import necessary modules
from socket import *
import sys
import argparse

# Define a function that attempts to connect to a single port on a target host
# Parameters: tgtHost = IP address or hostname, tgtPort = port number to check
def conScan(tgtHost, tgtPort):
    """
    Attempts to connect to a specific port on a target host.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPort (int): The port number to scan
    
    Returns:
        None: Prints the result directly
    """
    # Try-except block to handle any connection errors gracefully
    try:
        # Create a new socket object
        # AF_INET = IPv4 address family (use IPv4)
        # SOCK_STREAM = TCP protocol (reliable, connection-oriented)
        connskt = socket(AF_INET, SOCK_STREAM)
        
        # Attempt to establish a TCP connection to the target host and port
        # connect() will raise an exception if it fails (e.g., port closed, host unreachable)
        connskt.connect((tgtHost, tgtPort))
        
        # If connection succeeds, print that the port is open
        # The plus sign (+) indicates an open port in the output
        print ('[+] %d/tcp open' % tgtPort)
        
        # Close the socket connection to free up system resources
        # Important to prevent resource leaks and keep connections clean
        connskt.close()
    
    # If ANY exception occurs during the connection attempt (timeout, refused, etc.)
    except:
        # Print that the port is closed (or unreachable)
        # The minus sign (-) indicates the port is not accessible
        print('[-] %d/tcp closed' % tgtPort)

# Define the main port scanning function
# Parameters: tgtHost = target hostname or IP, tgtPorts = list of ports to scan
def portScan(tgtHost, tgtPorts):
    """
    Performs a port scan on a target host.
    
    Args:
        tgtHost (str): The target hostname or IP address
        tgtPorts (list): A list of port numbers to scan
    
    Returns:
        None: Prints results directly
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
        return
    
    # Now try to perform a reverse DNS lookup
    # This attempts to find the hostname from the IP address
    try:
        # gethostbyaddr() returns a tuple: (hostname, aliases, IP addresses)
        tgtName = gethostbyaddr(tgtIP)
        # If successful, print the resolved hostname as the scan target
        # This often shows the canonical name or the original hostname
        print('\n[+] Scan Result of: %s ' % tgtName[0])
    
    # If reverse DNS lookup fails (common for many IPs)
    except:
        # Print just the IP address since we couldn't find a hostname
        print('\n[+] Scan Result of: %s ' % tgtIP)
    
    # Set a timeout for socket operations to prevent hanging
    # 1 second means if a connection takes longer than 1 second, it will timeout
    # This prevents the scanner from getting stuck on slow or filtered ports
    setdefaulttimeout(1)
    
    # Loop through each port in the list of ports to scan
    # tgtPorts is expected to be a list like [80, 22, 443, ...]
    for tgtPort in tgtPorts:
        # Print a status message showing which port we're currently scanning
        # This gives the user feedback during the scan process
        print('Scanning Port: %d'% tgtPort)
        
        # Call the conScan function to actually test this specific port
        # Convert tgtPort to int in case it came as a string (safe practice)
        conScan(tgtHost, int(tgtPort))

# Define the main function that parses command-line arguments
def main():
    """
    Main function that handles command-line arguments and initiates the scan.
    """
    # Create an argument parser with a description
    parser = argparse.ArgumentParser(
        description='Simple TCP Port Scanner',
        epilog='Example: python port_scanner.py google.com 80,443,22'
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
    
    # Call the portScan function with the provided arguments
    portScan(args.target, port_list)

# This is the entry point of the script
# The code inside this if block only runs when the script is executed directly
# (not when it's imported as a module by another script)
if __name__ == '__main__':
    main()