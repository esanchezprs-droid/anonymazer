import threading
import time
import urllib.request
import subprocess
import json
import logging
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Tuple, List
import psutil
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
CHECK_TOR_URL = "https://check.torproject.org/api/ip"
TOR_PORT = 9050
TOR_DNS_PORT = 5353
ALLOWED_PROTOCOLS = ["tcp"]

# Optimized verification constants
CHECK_INTERVAL_BASE = 30
CHECK_INTERVAL_MAX = 120
CPU_THRESHOLD = 0.8
MAX_RETRIES = 3
RETRY_DELAY = 5
FALLBACK_TOR_CHECK_URLS = [
    "https://check.torproject.org/api/ip",
    "https://api.onionoo.torproject.org/details?type=client",
]

class Anonymizer:
    def __init__(self):
        self.original_configs = {}
        self.encryption_key = self.generate_encryption_key()
        self.is_active = False
        self.tor_thread = None
        self.kill_switch_active = False
        self.network_interfaces = self.get_network_interfaces()
        
        # Thread pool for concurrent checks
        self.executor = ThreadPoolExecutor(max_workers=3)
        
        # Cache with thread lock for safety
        self.cache_lock = threading.Lock()
        self.last_check_results = {
            "tor_status": None,
            "dns_leak": None,
            "ip_anonymity": None,
            "unauthorized_traffic": None,
            "last_check_time": 0
        }
        
        # Cache CPU reading to avoid blocking
        self.last_cpu_load = 0.0
        self.last_cpu_check = 0
        
    def generate_encryption_key(self):
        """Placeholder for key generation."""
        return "dummy_key"
    
    def get_network_interfaces(self):
        """Placeholder for network interface detection."""
        return []

    def check_system_load(self) -> float:
        """Get current CPU usage with caching to avoid blocking."""
        current_time = time.time()
        # Cache CPU reading for 5 seconds
        if current_time - self.last_cpu_check < 5:
            return self.last_cpu_load
        
        # Non-blocking CPU check
        self.last_cpu_load = psutil.cpu_percent(interval=0) / 100
        self.last_cpu_check = current_time
        return self.last_cpu_load

    def get_adaptive_interval(self) -> float:
        """Adjust check interval based on system load."""
        cpu_load = self.check_system_load()
        if cpu_load > CPU_THRESHOLD:
            return min(CHECK_INTERVAL_BASE * (1 + cpu_load), CHECK_INTERVAL_MAX)
        return CHECK_INTERVAL_BASE

    def check_tor_status(self, retry_count: int = 0) -> Tuple[bool, str]:
        """Verify Tor is running with fallback URLs and proper retries."""
        last_error = ""
        
        for url in FALLBACK_TOR_CHECK_URLS:
            for attempt in range(MAX_RETRIES):
                try:
                    # Use Tor proxy for the check itself
                    proxy = urllib.request.ProxyHandler({
                        'http': f'socks5h://127.0.0.1:{TOR_PORT}',
                        'https': f'socks5h://127.0.0.1:{TOR_PORT}'
                    })
                    opener = urllib.request.build_opener(proxy)
                    request = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
                    
                    with opener.open(request, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        
                        if "IsTor" in data:
                            is_tor = data["IsTor"]
                        elif "clients" in data:
                            is_tor = bool(data.get("clients"))
                        else:
                            continue
                            
                        if is_tor:
                            return True, ""
                        return False, f"Tor not active at {url}"
                        
                except Exception as e:
                    last_error = f"{url}: {str(e)}"
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                    continue
                    
        return False, f"All Tor checks failed. Last error: {last_error}"

    def check_dns_leaks(self, retry_count: int = 0) -> Tuple[bool, str]:
        """Verify DNS queries go through Tor."""
        for attempt in range(MAX_RETRIES):
            try:
                # Use a real domain that should resolve
                test_domain = "check.torproject.org"
                
                # Check DNS resolution through Tor
                result = subprocess.run(
                    ["dig", "+short", "@127.0.0.1", "-p", str(TOR_DNS_PORT), test_domain],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True
                )
                
                # Verify we got a response
                if result.stdout.strip():
                    return True, ""
                    
                return False, "DNS resolution through Tor failed"
                
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return False, f"DNS leak check failed: {str(e)}"
                
        return False, "DNS leak check exhausted retries"

    def check_ip_anonymity(self, retry_count: int = 0) -> Tuple[bool, str]:
        """Verify external IP differs from real IP."""
        for attempt in range(MAX_RETRIES):
            try:
                # Get Tor IP first (safer order)
                tor_result = subprocess.run(
                    ["curl", "--socks5-hostname", f"127.0.0.1:{TOR_PORT}", 
                     "-s", "-m", "10", "https://api.ipify.org"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True
                )
                tor_ip = tor_result.stdout.strip()
                
                # Get real IP (this could leak, but necessary for comparison)
                real_result = subprocess.run(
                    ["curl", "-s", "-m", "10", "https://api.ipify.org"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True
                )
                real_ip = real_result.stdout.strip()
                
                if real_ip and tor_ip and real_ip != tor_ip:
                    return True, ""
                    
                return False, f"IPs match or invalid: real={real_ip}, tor={tor_ip}"
                
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return False, f"IP check failed: {str(e)}"
                
        return False, "IP anonymity check exhausted retries"

    def check_unauthorized_traffic(self) -> Tuple[bool, str]:
        """Check for non-Tor traffic using netstat."""
        try:
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True
            )
            
            suspicious_lines = []
            for line in result.stdout.splitlines():
                # Check for listening ports that aren't localhost or Tor
                if "LISTEN" in line:
                    if "127.0.0.1" not in line and "::1" not in line:
                        if str(TOR_PORT) not in line and str(TOR_DNS_PORT) not in line:
                            suspicious_lines.append(line.strip())
            
            if suspicious_lines:
                return False, f"Suspicious traffic: {suspicious_lines[0]}"
                
            return True, ""
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            return False, f"Traffic check failed: {str(e)}"

    def monitor_security(self):
        """Optimized continuous security monitoring."""
        logger.info("Security monitoring started")
        
        while self.is_active:
            start_time = time.time()
            interval = self.get_adaptive_interval()
            
            # Thread-safe cache check
            with self.cache_lock:
                time_since_check = time.time() - self.last_check_results["last_check_time"]
                if time_since_check < (interval / 2):
                    # Sleep and continue to next iteration
                    time.sleep(min(interval / 4, 10))
                    continue
            
            # Define checks to run concurrently
            checks: List[Tuple[Callable[[], Tuple[bool, str]], str]] = [
                (self.check_tor_status, "tor_status"),
                (self.check_dns_leaks, "dns_leak"),
                (self.check_ip_anonymity, "ip_anonymity"),
                (self.check_unauthorized_traffic, "unauthorized_traffic")
            ]
            
            results = {}
            
            # FIX: Use self.executor directly, not as context manager
            future_to_check = {self.executor.submit(check[0]): check[1] for check in checks}
            
            for future in as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    success, error_msg = future.result(timeout=30)
                    results[check_name] = (success, error_msg)
                except Exception as e:
                    logger.error(f"Check {check_name} raised exception: {e}")
                    results[check_name] = (False, f"Exception: {str(e)}")
            
            # Update cache atomically
            with self.cache_lock:
                for check_name, (success, _) in results.items():
                    self.last_check_results[check_name] = success
                self.last_check_results["last_check_time"] = time.time()
            
            # Process results and trigger kill switch if needed
            all_passed = True
            for check_name, (success, error_msg) in results.items():
                if not success:
                    logger.critical(f"SECURITY BREACH: {check_name} failed - {error_msg}")
                    all_passed = False
                else:
                    logger.info(f"✓ {check_name} passed")
            
            if not all_passed:
                logger.critical("Security checks failed - activating kill switch")
                self.emergency_shutdown()
                return
            
            # Sleep until next check with jitter
            elapsed = time.time() - start_time
            sleep_time = max(0, interval - elapsed)
            jitter = random.uniform(0, min(5, sleep_time * 0.1))
            time.sleep(sleep_time + jitter)

    def emergency_shutdown(self):
        """Activate kill switch and block all traffic."""
        if self.kill_switch_active:
            return  # Prevent multiple activations
            
        self.kill_switch_active = True
        logger.critical("=" * 60)
        logger.critical("EMERGENCY KILL SWITCH ACTIVATED")
        logger.critical("=" * 60)
        
        try:
            # Flush existing rules
            subprocess.run(["iptables", "-F"], check=True, timeout=5)
            subprocess.run(["ip6tables", "-F"], check=True, timeout=5)
            
            # Block all traffic
            for cmd_base in [["iptables"], ["ip6tables"]]:
                for chain in ["INPUT", "OUTPUT", "FORWARD"]:
                    subprocess.run(cmd_base + ["-P", chain, "DROP"], check=True, timeout=5)
            
            logger.critical("All network traffic blocked")
            self.restore_system()
            
        except subprocess.CalledProcessError as e:
            logger.critical(f"CRITICAL: Failed to activate kill switch: {e}")
        finally:
            sys.exit(1)

    def restore_system(self):
        """Placeholder for system restoration."""
        logger.info("Restoring system configuration")
        # Implementation depends on what was changed during activation

    def deactivate(self):
        """Deactivate and clean up."""
        logger.info("Deactivating anonymization system")
        self.is_active = False
        
        # Shutdown thread pool gracefully
        self.executor.shutdown(wait=True, cancel_futures=True)
        
        self.restore_system()
        logger.info("Anonymization system deactivated")