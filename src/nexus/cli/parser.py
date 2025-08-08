"""
NEXUS-AI Network Scan Parser
Extracts meaningful features from Nmap XML scan results

This module converts raw Nmap scan data into feature vectors that our AI can understand
and analyze for threat detection.
"""

import xml.etree.ElementTree as ET
import numpy as np


def parse_nmap_xml(scan_file_path):
    """
    Parse Nmap XML scan and extract features for AI analysis
    
    This function reads an Nmap XML file and extracts:
    - Open ports (1-122)
    - Protocol types (TCP/UDP/SCTP)
    - Service banners (top 10 common services)
    - OS detection (family, vendor, accuracy)
    - Scan timing (duration)
    
    Args:
        scan_file_path (str): Path to the Nmap XML file
        
    Returns:
        numpy.ndarray: 2D feature vector ready for AI analysis
        
    Raises:
        ValueError: If scan file is invalid or missing required data
    """
    # Parse the XML file
    tree = ET.parse(scan_file_path)
    root = tree.getroot()
    
    # Initialize feature vectors for different scan aspects
    port_features = np.zeros(122, dtype=float)  # Ports 1-122
    protocol_features = np.zeros(3, dtype=float)  # TCP, UDP, SCTP
    service_features = np.zeros(11, dtype=float)  # Top 10 services + 'other'
    
    # Find the first host in the scan (we analyze one host at a time)
    host_element = root.find('host')
    if host_element is None:
        raise ValueError("No host found in scan file")
    
    # Extract scan duration information
    scan_duration = extract_scan_duration(root, host_element)
    
    # Extract port and service information
    ports_element = host_element.find('ports')
    if ports_element is None:
        raise ValueError("No ports found in scan file")
    
    # Process each port found in the scan
    for port_element in ports_element.findall('port'):
        port_number = int(port_element.attrib.get('portid', 0))
        protocol_type = port_element.attrib.get('protocol', '').lower()
        
        # Only process ports in our range (1-122)
        if 1 <= port_number <= 122:
            state_element = port_element.find('state')
            if state_element is not None and state_element.attrib.get('state') == 'open':
                # Mark this port as open
                port_features[port_number - 1] = 1
                
                # Record protocol type
                if protocol_type in ['tcp', 'udp', 'sctp']:
                    protocol_index = {'tcp': 0, 'udp': 1, 'sctp': 2}[protocol_type]
                    protocol_features[protocol_index] = 1
                
                # Record service information
                service_element = port_element.find('service')
                if service_element is not None:
                    service_name = service_element.attrib.get('name', '').lower()
                    service_features = encode_service_name(service_name, service_features)
    
    # Extract OS detection features
    os_features = extract_operating_system_features(host_element)
    
    # Combine all features into a single vector
    complete_feature_vector = np.concatenate([
        port_features,
        protocol_features,
        service_features,
        os_features,
        np.array([scan_duration], dtype=float)
    ])
    
    # Return as 2D array for AI processing
    return complete_feature_vector.reshape(1, -1)


def extract_scan_duration(root_element, host_element):
    """
    Extract scan duration from XML elements
    
    Tries multiple methods to find scan timing information:
    1. From nmaprun attributes (start/end times)
    2. From host times element
    
    Args:
        root_element: The root XML element
        host_element: The host XML element
        
    Returns:
        float: Scan duration in seconds (0.0 if not found)
    """
    # Method 1: Try to get timing from nmaprun attributes
    start_time = root_element.attrib.get('start')
    end_time = root_element.attrib.get('end')
    
    if start_time and end_time:
        try:
            return float(end_time) - float(start_time)
        except (ValueError, TypeError):
            pass
    
    # Method 2: Try to get timing from host times element
    times_element = host_element.find('times')
    if times_element is not None:
        try:
            finished_time = float(times_element.attrib.get('finished', 0))
            start_time = float(times_element.attrib.get('start', 0))
            return finished_time - start_time
        except (ValueError, TypeError):
            pass
    
    # If no timing information found, return 0
    return 0.0


def extract_operating_system_features(host_element):
    """
    Extract operating system detection features
    
    Analyzes OS detection results to create feature vectors for:
    - OS family (Linux, Windows, BSD, etc.)
    - OS vendor (Microsoft, Apple, Cisco, etc.)
    - Detection accuracy
    
    Args:
        host_element: The host XML element
        
    Returns:
        numpy.ndarray: OS-related feature vector
    """
    # Default values for unknown OS
    detected_os_family = 'unknown'
    detected_os_vendor = 'unknown'
    detection_accuracy = 0.0
    
    # Look for OS detection results
    os_element = host_element.find('os')
    if os_element is not None:
        os_match_element = os_element.find('osmatch')
        if os_match_element is not None:
            # Get detection accuracy
            detection_accuracy = float(os_match_element.attrib.get('accuracy', 0))
            
            # Get OS class information
            os_class_element = os_match_element.find('osclass')
            if os_class_element is not None:
                detected_os_family = os_class_element.attrib.get('osfamily', 'unknown').lower()
                detected_os_vendor = os_class_element.attrib.get('vendor', 'unknown').lower()
    
    # Create feature vectors for OS family and vendor
    os_family_features = encode_os_family(detected_os_family)
    os_vendor_features = encode_os_vendor(detected_os_vendor)
    
    # Combine OS features
    return np.concatenate([
        os_family_features,
        os_vendor_features,
        np.array([detection_accuracy], dtype=float)
    ])


def encode_service_name(service_name, service_features):
    """
    Encode service name into feature vector
    
    Maps common service names to feature vector positions.
    Unknown services are mapped to the 'other' category.
    
    Args:
        service_name (str): Name of the service (e.g., 'http', 'ssh')
        service_features (numpy.ndarray): Current service feature vector
        
    Returns:
        numpy.ndarray: Updated service feature vector
    """
    # Top 10 most common services we're interested in
    common_services = [
        'http', 'ssh', 'ftp', 'smtp', 'domain', 
        'telnet', 'https', 'pop3', 'imap', 'mysql'
    ]
    
    if service_name in common_services:
        service_index = common_services.index(service_name)
        service_features[service_index] = 1
    else:
        # Unknown service goes to 'other' category (index 10)
        service_features[10] = 1
    
    return service_features


def encode_os_family(os_family):
    """
    Encode OS family into feature vector
    
    Maps common OS families to feature vector positions.
    Unknown families are mapped to 'other' category.
    
    Args:
        os_family (str): Detected OS family (e.g., 'linux', 'windows')
        
    Returns:
        numpy.ndarray: OS family feature vector
    """
    # Common OS families we're interested in
    common_families = ['linux', 'windows', 'bsd', 'ios', 'android']
    family_features = np.zeros(6, dtype=float)  # 5 common + 1 other
    
    if os_family in common_families:
        family_index = common_families.index(os_family)
        family_features[family_index] = 1
    else:
        # Unknown OS family goes to 'other' category (index 5)
        family_features[5] = 1
    
    return family_features


def encode_os_vendor(os_vendor):
    """
    Encode OS vendor into feature vector
    
    Maps common OS vendors to feature vector positions.
    Unknown vendors are mapped to 'other' category.
    
    Args:
        os_vendor (str): Detected OS vendor (e.g., 'microsoft', 'apple')
        
    Returns:
        numpy.ndarray: OS vendor feature vector
    """
    # Common OS vendors we're interested in
    common_vendors = ['microsoft', 'apple', 'cisco', 'juniper', 'netgear']
    vendor_features = np.zeros(6, dtype=float)  # 5 common + 1 other
    
    if os_vendor in common_vendors:
        vendor_index = common_vendors.index(os_vendor)
        vendor_features[vendor_index] = 1
    else:
        # Unknown vendor goes to 'other' category (index 5)
        vendor_features[5] = 1
    
    return vendor_features


def get_feature_summary(feature_vector):
    """
    Get a human-readable summary of extracted features
    
    Useful for debugging and understanding what the parser extracted.
    
    Args:
        feature_vector (numpy.ndarray): Feature vector from parse_nmap_xml
        
    Returns:
        dict: Summary of extracted features
    """
    # Reshape to 1D for easier processing
    features = feature_vector.flatten()
    
    # Extract different feature sections
    port_features = features[:122]
    protocol_features = features[122:125]
    service_features = features[125:136]
    os_family_features = features[136:142]
    os_vendor_features = features[142:148]
    detection_accuracy = features[148]
    scan_duration = features[149]
    
    # Count open ports
    open_ports = np.where(port_features == 1)[0] + 1
    
    # Identify protocols
    protocols = []
    protocol_names = ['TCP', 'UDP', 'SCTP']
    for i, active in enumerate(protocol_features):
        if active == 1:
            protocols.append(protocol_names[i])
    
    # Identify services
    service_names = ['http', 'ssh', 'ftp', 'smtp', 'domain', 'telnet', 'https', 'pop3', 'imap', 'mysql', 'other']
    active_services = []
    for i, active in enumerate(service_features):
        if active == 1:
            active_services.append(service_names[i])
    
    return {
        'open_ports': open_ports.tolist(),
        'protocols': protocols,
        'services': active_services,
        'detection_accuracy': detection_accuracy,
        'scan_duration_seconds': scan_duration,
        'total_features': len(features)
    }

def extract_ip_from_scan_file(scan_path):
    """
    Extract the target IP address from an Nmap XML scan file
    
    Args:
        scan_path (str): Path to the Nmap XML scan file
        
    Returns:
        str: Target IP address
    """
    try:
        tree = ET.parse(scan_path)
        root = tree.getroot()
        
        # Find the first host element
        host_element = root.find('host')
        if host_element is None:
            return "Unknown"
        
        # Extract IP address
        address_element = host_element.find('address')
        if address_element is not None and address_element.attrib.get('addrtype') == 'ipv4':
            return address_element.attrib.get('addr', 'Unknown')
        
        return "Unknown"
    except Exception as e:
        return "Unknown"

def extract_open_ports_from_scan_file(scan_path):
    """
    Extract open ports and services from an Nmap XML scan file
    
    Args:
        scan_path (str): Path to the Nmap XML scan file
        
    Returns:
        list: List of dictionaries containing port information
    """
    try:
        tree = ET.parse(scan_path)
        root = tree.getroot()
        
        ports_info = []
        
        # Find the first host element
        host_element = root.find('host')
        if host_element is None:
            return ports_info
        
        # Extract ports information
        ports_element = host_element.find('ports')
        if ports_element is None:
            return ports_info
        
        for port_element in ports_element.findall('port'):
            port_id = port_element.attrib.get('portid', '')
            protocol = port_element.attrib.get('protocol', '')
            
            # Check if port is open
            state_element = port_element.find('state')
            if state_element is not None and state_element.attrib.get('state') == 'open':
                # Get service information
                service_element = port_element.find('service')
                service_name = 'unknown'
                if service_element is not None:
                    service_name = service_element.attrib.get('name', 'unknown')
                
                ports_info.append({
                    'port': port_id,
                    'protocol': protocol,
                    'service': service_name
                })
        
        return ports_info
    except Exception as e:
        return []
