#!/usr/bin/env python3
import subprocess
import sys
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import time
import argparse
from typing import List, Dict, Optional

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Print script banner"""
    banner = f"""
{Colors.BLUE}{Colors.BOLD}╔═══════════════════════════════════════════════╗
║           Network Scanner v1.0                ║
║        Powered by nmap + Python              ║
╚═══════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def check_nmap():
    """Check if nmap is installed"""
    try:
        subprocess.run(['nmap', '--version'], 
                      capture_output=True, 
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def print_stage(stage_num: int, total_stages: int, description: str):
    """Print stage header"""
    print(f"\n{Colors.BOLD}[Stage {stage_num}/{total_stages}] {description}{Colors.END}")
    print("━" * 50)

def run_nmap_scan(target: str, scan_type: str = 'default') -> Optional[str]:
    """
    Run nmap scan and return XML output
    
    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan (default, aggressive, quick)
    
    Returns:
        Path to XML output file or None if failed
    """
    output_file = f"/tmp/nmap_scan_{int(time.time())}.xml"
    
    # Build nmap command based on scan type
    if scan_type == 'aggressive':
        cmd = ['nmap', '-sV', '-O', '-A', '--osscan-guess', 
               '-oX', output_file, target]
    elif scan_type == 'quick':
        cmd = ['nmap', '-T4', '-F', '-sV', 
               '-oX', output_file, target]
    else:  # default
        cmd = ['nmap', '-sV', '-O', '--osscan-guess',
               '-oX', output_file, target]
    
    try:
        # Show progress
        print(f"{Colors.YELLOW}[*] Running: {' '.join(cmd)}{Colors.END}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Simple progress indicator
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        i = 0
        while process.poll() is None:
            print(f"\r{spinner[i % len(spinner)]} Scanning...", end='', flush=True)
            time.sleep(0.1)
            i += 1
        
        print(f"\r{Colors.GREEN}✓ Scan complete{Colors.END}" + " " * 20)
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            print(f"{Colors.RED}[!] Error running nmap: {stderr}{Colors.END}")
            return None
            
        return output_file
        
    except Exception as e:
        print(f"{Colors.RED}[!] Exception during scan: {str(e)}{Colors.END}")
        return None

def parse_nmap_xml(xml_file: str) -> Dict:
    """
    Parse nmap XML output
    
    Returns:
        Dictionary containing scan results
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        results = {
            'host': None,
            'hostname': None,
            'state': None,
            'os': None,
            'ports': []
        }
        
        # Get host information
        host = root.find('host')
        if host is None:
            return results
        
        # Host state
        status = host.find('status')
        if status is not None:
            results['state'] = status.get('state')
        
        # IP address
        address = host.find('address')
        if address is not None:
            results['host'] = address.get('addr')
        
        # Hostname
        hostnames = host.find('hostnames')
        if hostnames is not None:
            hostname = hostnames.find('hostname')
            if hostname is not None:
                results['hostname'] = hostname.get('name')
        
        # OS detection
        os = host.find('os')
        if os is not None:
            osmatch = os.find('osmatch')
            if osmatch is not None:
                results['os'] = osmatch.get('name')
                results['os_accuracy'] = osmatch.get('accuracy')
        
        # Ports
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                
                state = port.find('state')
                state_val = state.get('state') if state is not None else 'unknown'
                
                service = port.find('service')
                service_name = service.get('name') if service is not None else 'unknown'
                service_product = service.get('product', '')
                service_version = service.get('version', '')
                
                # Build version string
                version = ''
                if service_product:
                    version = service_product
                if service_version:
                    version += f" {service_version}" if version else service_version
                
                if state_val == 'open':
                    results['ports'].append({
                        'port': port_id,
                        'protocol': protocol,
                        'state': state_val,
                        'service': service_name,
                        'version': version.strip()
                    })
        
        return results
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error parsing XML: {str(e)}{Colors.END}")
        return {}

def print_results_table(results: Dict):
    """Print results in a formatted table"""
    
    # Host Information
    print(f"\n{Colors.BOLD}[Target Information]{Colors.END}")
    print(f"IP Address: {Colors.GREEN}{results.get('host', 'N/A')}{Colors.END}")
    if results.get('hostname'):
        print(f"Hostname:   {Colors.GREEN}{results['hostname']}{Colors.END}")
    print(f"Status:     {Colors.GREEN}{results.get('state', 'unknown')}{Colors.END}")
    
    # OS Detection
    if results.get('os'):
        print(f"\n{Colors.BOLD}[Operating System]{Colors.END}")
        accuracy = results.get('os_accuracy', 'N/A')
        print(f"OS:         {Colors.YELLOW}{results['os']}{Colors.END} ({accuracy}% accuracy)")
    
    # Ports table
    ports = results.get('ports', [])
    if ports:
        print(f"\n{Colors.BOLD}[+] Found {len(ports)} open port(s):{Colors.END}")
        
        # Table header
        print("┌" + "─" * 8 + "┬" + "─" * 11 + "┬" + "─" * 15 + "┬" + "─" * 30 + "┐")
        print(f"│ {'Port':<6} │ {'State':<9} │ {'Service':<13} │ {'Version':<28} │")
        print("├" + "─" * 8 + "┼" + "─" * 11 + "┼" + "─" * 15 + "┼" + "─" * 30 + "┤")
        
        # Table rows
        for port in ports:
            port_str = f"{port['port']}/{port['protocol'][:3]}"
            version = port['version'][:28] if port['version'] else '-'
            print(f"│ {Colors.GREEN}{port_str:<6}{Colors.END} │ "
                  f"{port['state']:<9} │ "
                  f"{port['service']:<13} │ "
                  f"{version:<28} │")
        
        # Table footer
        print("└" + "─" * 8 + "┴" + "─" * 11 + "┴" + "─" * 15 + "┴" + "─" * 30 + "┘")
    else:
        print(f"\n{Colors.YELLOW}[!] No open ports found{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='Network scanner using nmap',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s scanme.nmap.org --type aggressive
  %(prog)s 10.0.0.0/24 --type quick
        """
    )
    parser.add_argument('target', help='Target IP address, hostname, or network range')
    parser.add_argument('--type', choices=['default', 'aggressive', 'quick'],
                       default='default',
                       help='Scan type (default: default)')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')
    
    print_banner()
    
    # Check if nmap is installed
    print_stage(1, 5, "Checking Dependencies")
    if not check_nmap():
        print(f"{Colors.RED}[!] nmap is not installed. Please install it first:{Colors.END}")
        print("    Ubuntu/Debian: sudo apt-get install nmap")
        print("    Fedora/RHEL:   sudo dnf install nmap")
        print("    Arch:          sudo pacman -S nmap")
        sys.exit(1)
    print(f"{Colors.GREEN}[✓] nmap found{Colors.END}")
    
    # Run scan
    print_stage(2, 5, "Port Scanning")
    xml_file = run_nmap_scan(args.target, args.type)
    
    if not xml_file:
        print(f"{Colors.RED}[!] Scan failed{Colors.END}")
        sys.exit(1)
    
    # Parse results
    print_stage(3, 5, "Parsing Results")
    results = parse_nmap_xml(xml_file)
    
    # Display results
    print_stage(4, 5, "Results")
    print_results_table(results)
    
    # Cleanup
    print_stage(5, 5, "Cleanup")
    try:
        Path(xml_file).unlink()
        print(f"{Colors.GREEN}[✓] Temporary files cleaned{Colors.END}")
    except:
        pass
    
    print(f"\n{Colors.BOLD}[✓] Scan complete!{Colors.END}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)