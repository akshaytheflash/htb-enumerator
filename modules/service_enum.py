#!/usr/bin/env python3
"""
Service Enumeration Module
Performs enumeration on HTTP/HTTPS and FTP services
"""

import requests
import ftplib
import os
import sys
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HTTPEnumerator:
    """Handles HTTP/HTTPS service enumeration"""
    
    def __init__(self, target: str, port: int, use_https: bool = False):
        self.target = target
        self.port = port
        self.protocol = "https" if use_https else "http"
        self.base_url = f"{self.protocol}://{target}:{port}"
        self.found_dirs = []
        self.screenshot_dir = "screenshots"
        
        # Create screenshots directory
        os.makedirs(self.screenshot_dir, exist_ok=True)
        
    def fetch_wordlist(self) -> List[str]:
        """Fetch common.txt wordlist from GitHub"""
        wordlist_url = "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt"
        try:
            logger.info(f"Fetching wordlist from {wordlist_url}")
            response = requests.get(wordlist_url, timeout=10)
            response.raise_for_status()
            wordlist = [line.strip() for line in response.text.splitlines() if line.strip()]
            logger.info(f"Loaded {len(wordlist)} entries from wordlist")
            return wordlist
        except Exception as e:
            logger.error(f"Failed to fetch wordlist: {e}")
            return []
    
    def check_directory(self, path: str) -> Dict:
        """Check if a directory exists"""
        url = urljoin(self.base_url, path)
        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                verify=False
            )
            
            if response.status_code in [200, 301, 302, 401, 403]:
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content)
                }
        except requests.exceptions.RequestException:
            pass
        return None
    
    def directory_bruteforce(self, max_threads: int = 10):
        """Perform directory bruteforcing"""
        logger.info(f"Starting directory bruteforce on {self.base_url}")
        
        wordlist = self.fetch_wordlist()
        if not wordlist:
            logger.error("No wordlist available for bruteforcing")
            return
        
        # Add leading slash to paths
        paths = [f"/{word}" if not word.startswith('/') else word for word in wordlist]
        
        found_count = 0
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.check_directory, path): path for path in paths}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_count += 1
                    self.found_dirs.append(result)
                    logger.info(f"[{result['status']}] {result['url']} (Size: {result['size']} bytes)")
        
        logger.info(f"Directory bruteforce complete. Found {found_count} directories")
        return self.found_dirs
    
    def capture_screenshot(self, url: str = None):
        """Capture screenshot of web page"""
        if url is None:
            url = self.base_url
        
        try:
            logger.info(f"Capturing screenshot of {url}")
            
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Initialize driver
            driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=chrome_options
            )
            
            driver.get(url)
            time.sleep(2)  # Wait for page to load
            
            # Generate filename
            parsed = urlparse(url)
            filename = f"{parsed.netloc}_{parsed.path.replace('/', '_')}_{int(time.time())}.png"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            driver.save_screenshot(filepath)
            driver.quit()
            
            logger.info(f"Screenshot saved to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to capture screenshot: {e}")
            return None
    
    def enumerate(self):
        """Run full HTTP enumeration"""
        logger.info(f"\n{'='*60}")
        logger.info(f"HTTP/HTTPS Enumeration: {self.base_url}")
        logger.info(f"{'='*60}\n")
        
        # Check if service is accessible
        try:
            response = requests.get(self.base_url, timeout=5, verify=False)
            logger.info(f"Service is accessible - Status: {response.status_code}")
        except Exception as e:
            logger.error(f"Service not accessible: {e}")
            return
        
        # Capture screenshot of main page
        self.capture_screenshot()
        
        # Perform directory bruteforce
        self.directory_bruteforce()
        
        # Capture screenshots of interesting found directories
        for dir_info in self.found_dirs[:5]:  # Limit to first 5 to avoid too many screenshots
            if dir_info['status'] == 200:
                self.capture_screenshot(dir_info['url'])


class FTPEnumerator:
    """Handles FTP service enumeration"""
    
    def __init__(self, target: str, port: int = 21):
        self.target = target
        self.port = port
        
    def check_anonymous_login(self) -> bool:
        """Check if anonymous FTP login is allowed"""
        try:
            logger.info(f"Checking anonymous FTP login on {self.target}:{self.port}")
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=10)
            ftp.login('anonymous', 'anonymous@')
            logger.info("✓ Anonymous FTP login is ALLOWED")
            return True, ftp
        except ftplib.error_perm as e:
            logger.warning(f"✗ Anonymous FTP login denied: {e}")
            return False, None
        except Exception as e:
            logger.error(f"FTP connection failed: {e}")
            return False, None
    
    def list_directory(self, ftp: ftplib.FTP, path: str = '/') -> List[str]:
        """List directory contents"""
        try:
            ftp.cwd(path)
            files = []
            ftp.retrlines('LIST', files.append)
            return files
        except Exception as e:
            logger.error(f"Failed to list directory {path}: {e}")
            return []
    
    def recursive_list(self, ftp: ftplib.FTP, path: str = '/', depth: int = 0, max_depth: int = 3):
        """Recursively list FTP directory structure"""
        if depth > max_depth:
            return
        
        indent = "  " * depth
        logger.info(f"{indent}[Directory: {path}]")
        
        try:
            files = self.list_directory(ftp, path)
            for file_info in files:
                logger.info(f"{indent}  {file_info}")
                
                # Try to recurse into subdirectories
                parts = file_info.split()
                if len(parts) >= 9 and parts[0].startswith('d'):
                    dirname = ' '.join(parts[8:])
                    if dirname not in ['.', '..']:
                        new_path = f"{path}/{dirname}" if path != '/' else f"/{dirname}"
                        self.recursive_list(ftp, new_path, depth + 1, max_depth)
        except Exception as e:
            logger.error(f"{indent}Error reading {path}: {e}")
    
    def enumerate(self):
        """Run full FTP enumeration"""
        logger.info(f"\n{'='*60}")
        logger.info(f"FTP Enumeration: {self.target}:{self.port}")
        logger.info(f"{'='*60}\n")
        
        allowed, ftp = self.check_anonymous_login()
        
        if allowed and ftp:
            logger.info("\nListing directory contents...")
            self.recursive_list(ftp, '/')
            ftp.quit()
        else:
            logger.warning("Cannot enumerate - anonymous access not available")


def enumerate_service(target: str, port: int, service_type: str):
    """Main function to enumerate a service"""
    if service_type.lower() in ['http', 'https', 'web']:
        use_https = port == 443 or service_type.lower() == 'https'
        enumerator = HTTPEnumerator(target, port, use_https)
        enumerator.enumerate()
    elif service_type.lower() == 'ftp':
        enumerator = FTPEnumerator(target, port)
        enumerator.enumerate()
    else:
        logger.error(f"Unsupported service type: {service_type}")


def parse_ports(port_string: str) -> List[int]:
    """Parse port string and return list of ports"""
    ports = []
    for port in port_string.split():
        try:
            ports.append(int(port.strip()))
        except ValueError:
            logger.warning(f"Invalid port number: {port}")
    return ports


def detect_service_type(port: int) -> str:
    """Auto-detect service type based on common port numbers"""
    http_ports = [80, 8080, 8000, 8888, 3000, 5000]
    https_ports = [443, 8443]
    ftp_ports = [21]
    
    if port in https_ports:
        return 'https'
    elif port in http_ports:
        return 'http'
    elif port in ftp_ports:
        return 'ftp'
    else:
        # Default to http for unknown ports
        return 'http'


if __name__ == "__main__":
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Example usage
    if len(sys.argv) < 3:
        print("Usage: python service_enum.py <target> <ports> [service_type]")
        print("\nArguments:")
        print("  target        : Target IP or hostname")
        print("  ports         : Port(s) separated by space (e.g., '80 443 8080')")
        print("  service_type  : Optional. Service type (http/https/ftp)")
        print("                  If not specified, auto-detected based on port")
        print("\nExamples:")
        print("  python service_enum.py 192.168.1.100 80")
        print("  python service_enum.py 192.168.1.100 80 443 8080")
        print("  python service_enum.py 192.168.1.100 21 ftp")
        print("  python service_enum.py example.com '80 443' http")
        sys.exit(1)
    
    target = sys.argv[1]
    ports_string = sys.argv[2]
    service_type = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Parse ports
    ports = parse_ports(ports_string)
    
    if not ports:
        logger.error("No valid ports provided")
        sys.exit(1)
    
    logger.info(f"Starting enumeration on {target}")
    logger.info(f"Target ports: {ports}")
    
    # Enumerate each port
    for port in ports:
        # Use provided service type or auto-detect
        svc_type = service_type if service_type else detect_service_type(port)
        logger.info(f"\nEnumerating port {port} as {svc_type.upper()} service")
        
        try:
            enumerate_service(target, port, svc_type)
        except Exception as e:
            logger.error(f"Error enumerating {target}:{port} - {e}")
        
        # Add separator between different port enumerations
        if port != ports[-1]:
            print("\n" + "="*80 + "\n")
    
    logger.info("\nEnumeration complete!")