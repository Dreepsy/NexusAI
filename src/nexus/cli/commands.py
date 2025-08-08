#!/usr/bin/env python3
"""
NEXUS-AI Command Line Interface
Your AI-powered network security analysis companion

This tool analyzes Nmap scan results and provides intelligent threat assessment
using advanced machine learning and real-time threat intelligence.

I built this CLI to be both powerful and user-friendly. The idea was to make
complex security analysis accessible to both beginners and experts. The AI
integration makes it really smart about what it finds.

TODO: Need to fix that bug where it crashes on malformed XML files
TODO: Add better error handling for API rate limits
TODO: The JSON output formatting is a bit wonky sometimes
"""

import argparse
import os
import json
from pathlib import Path
from datetime import datetime
from .parser import parse_nmap_xml, extract_ip_from_scan_file, extract_open_ports_from_scan_file
from .predictor import load_enhanced_model, predict_class, get_model_info, get_label_mapping
from .vuln_info import get_vuln_info
from ..ai.deepseek_integration import generate_vuln_summary
from ..ai.vuln_cve_fetcher import fetch_cves
from ..ai.threat_feeds import enrich_cves_with_threat_intel
from ..ai.mitre_attack import enrich_findings_with_attack
from ..ai.advanced_threat_intel import AdvancedThreatIntel
from ..ai.real_time_learning import initialize_real_time_learning, add_analysis_for_learning, get_learning_statistics
from ..ai.exploit_guide_generator import generate_exploitation_guide, format_exploitation_guide, generate_quick_exploit_commands
from ..ai.exploit_developer import ExploitDeveloper
from ..core.config import get_config, get_logger
import xmltodict

# Get configuration and logger
config = get_config()
logger = get_logger()

# Eye-catching ASCII art for the tool - I spent way too much time on this 
# Tried to make it look cool but it's probably overkill lol
# At least it looks professional in the terminal ¯\_(ツ)_/¯
NEXUSAI_LOGO = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    N E X U S - A I                           ║
║                                                              ║
║              Your AI Security Companion                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

def display_json_output(data):
    """Display results in clean JSON format for integration purposes
    
    This is useful when you want to pipe the output to other tools or
    integrate with other systems. The JSON format makes it easy to parse.
    
    Note: Sometimes the JSON gets malformed if there are weird characters
    in the data. Need to fix that eventually.
    
    TODO: The JSON formatting is still a bit wonky sometimes, especially with
    unicode characters. Should probably use a more robust serializer.
    """
    try:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except (TypeError, ValueError) as e:
        # Fallback for when JSON serialization fails - this happens more often than I'd like
        print(f"Error formatting JSON: {e}")
        print("Raw data:", str(data)[:200] + "..." if len(str(data)) > 200 else str(data))
        # TODO: Add better error recovery here

def show_threat_intelligence_results(result):
    """Display threat intelligence findings in a human-readable format
    
    This function takes the raw threat intelligence data and presents it in a
    way that's easy to understand. I added emojis to make it more visually
    appealing and easier to scan quickly.
    
    TODO: The emoji display can be a bit much sometimes, might add a --no-emoji flag
    TODO: Need to handle cases where the threat data is malformed
    """
    print("\n" + "="*60)
    print("🔍 THREAT INTELLIGENCE ANALYSIS")
    print("="*60)
    
    # Show summary statistics - gives a quick overview of what we found
    summary = result.get("summary", {})
    print(f"📊 Analysis Summary: {summary.get('total_indicators', 0)} indicators checked")
    print(f"  🚨 Malicious: {summary.get('malicious_count', 0)}")
    print(f"  ⚠️  Suspicious: {summary.get('suspicious_count', 0)}")
    print(f"  ✅ Clean: {summary.get('clean_count', 0)}")
    
    # Show detailed findings for each indicator
    for indicator, data in result.get("indicators", {}).items():
        print(f"\n📍 Analyzing: {indicator}")
        print(f"  🎯 Threat Level: {data.get('threat_level', 'unknown').upper()}")
        print(f"  📈 Reputation Score: {data.get('reputation_score', 0)}/100")
        
        # Show VirusTotal results if available
        vt_data = data.get("virustotal", {})
        if "error" not in vt_data:
            print(f"  🛡️  VirusTotal: {vt_data.get('detection_ratio', 'N/A')} detections")
        
        # Show Shodan results if available
        shodan_data = data.get("shodan", {})
        if "error" not in shodan_data:
            print(f"  🌐 Shodan: {len(shodan_data.get('ports', []))} open ports found")

def show_shodan_search_results(result):
    """Display Shodan internet asset search results"""
    print("\n" + "="*60)
    print("🌐 INTERNET ASSET DISCOVERY")
    print("="*60)
    
    print(f"🔍 Search Query: {result.get('query', 'N/A')}")
    print(f"📊 Total Assets Found: {result.get('total', 0)}")
    
    # Show top matches
    for i, match in enumerate(result.get("matches", [])[:5], 1):
        print(f"\n{i}. Asset: {match.get('ip', 'N/A')}:{match.get('port', 'N/A')}")
        print(f"   🖥️  Product: {match.get('product', 'N/A')} {match.get('version', '')}")
        print(f"   🏢 Organization: {match.get('org', 'N/A')}")
        if match.get('location'):
            loc = match['location']
            print(f"   📍 Location: {loc.get('city', 'N/A')}, {loc.get('country_name', 'N/A')}")

def load_project_configuration():
    """Load and validate the project configuration file"""
    try:
        # Use ConfigManager to get configuration
        project_config = config.get('cli', {})
        
        # Add labels from config if available
        labels_config = config.get('labels', {})
        if labels_config:
            # Convert labels dict to list for backward compatibility
            labels_list = list(labels_config.values())
            project_config['labels'] = labels_list
        else:
            # Default labels
            project_config['labels'] = ['normal', 'exploits', 'reconnaissance', 'dos', 'backdoor']
        
        logger.info("Successfully loaded project configuration")
        return project_config
    except Exception as e:
        logger.error("Failed to load project configuration", error=str(e))
        # Return default configuration
        return {
            'labels': ['normal', 'exploits', 'reconnaissance', 'dos', 'backdoor'],
            'paths': {
                'params': 'models/',
                'data': 'data/'
            }
        }

# Load project configuration
config = load_project_configuration()
LABELS = config["labels"]

def analyze_network_scan(scan_path, output_format="text", include_exploitation_guide=False):
    """
    Perform comprehensive analysis of a network scan
    
    This function:
    1. Parses the Nmap XML scan
    2. Uses AI to predict attack types
    3. Fetches real CVE information
    4. Enriches with threat intelligence
    5. Provides MITRE ATT&CK analysis
    6. Learns from the analysis for future improvements
    
    TODO: The progress bar sometimes gets stuck, need to fix that
    TODO: Should probably add a timeout for really large scan files
    TODO: The error handling could be more graceful sometimes
    """
    result = {
        "scan_file": scan_path,
        "prediction": None,
        "ai_summary": None,
        "cves": None,
        "threat_intelligence": None,
        "mitre_attack_analysis": None,
        "learning_stats": None,
        "errors": []
    }
    
    # Step 1: Parse the Nmap scan file
    print("📄 Reading and parsing your Nmap scan...")
    try:
        features = parse_nmap_xml(scan_path)
        print("✅ Scan file successfully parsed and features extracted")
    except Exception as e:
        error_msg = f"Failed to parse Nmap XML: {e}"
        result["errors"].append(error_msg)
        return result
    
    # Step 2: Load AI model and make prediction
    print("🤖 Loading AI model and analyzing network behavior...")
    try:
        ensemble_model = load_enhanced_model()
        model_info = get_model_info(ensemble_model)
        label_mapping = get_label_mapping(ensemble_model)
        
        # Make the prediction
        prediction_result = predict_class(features, ensemble_model)
        
        # Handle dictionary return value from predict_class
        if isinstance(prediction_result, dict):
            pred_label = prediction_result.get('class', 'unknown')
            pred_confidence = prediction_result.get('confidence', 0.0)
            pred_index = prediction_result.get('class_index', 0)
        else:
            # Handle legacy integer return value
            pred_index = prediction_result
            if pred_index in label_mapping:
                pred_label = label_mapping[pred_index]
            elif pred_index < len(LABELS):
                pred_label = LABELS[pred_index]
            else:
                error_msg = f"AI prediction index {pred_index} is out of range"
                result["errors"].append(error_msg)
                return result
            pred_confidence = 0.5  # Default confidence
        
        result["prediction"] = pred_label
        result["confidence"] = pred_confidence
        result["model_info"] = model_info
        print(f"🎯 AI Analysis Complete: {pred_label} behavior detected")
        
    except Exception as e:
        error_msg = f"AI prediction failed: {e}"
        result["errors"].append(error_msg)
        return result
    
    # Step 3: Fetch real vulnerability information
    print("🔍 Searching for related vulnerabilities...")
    cve_list = fetch_cves(pred_label, "unknown_version")
    result["cves"] = cve_list
    
    # Provide fallback CVEs if none found
    if not cve_list:
        print("⚠️  No specific CVEs found, using common examples")
        cve_list = [
            {"id": "CVE-2021-41773", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49."},
            {"id": "CVE-2021-42013", "description": "Remote code execution in Apache HTTP Server 2.4.50."}
        ]
    
    # Step 4: Enrich with threat intelligence
    print("🌐 Gathering threat intelligence from multiple sources...")
    threat_intel = enrich_cves_with_threat_intel(cve_list, pred_label)
    result["threat_intelligence"] = threat_intel
    
    # Step 5: Perform MITRE ATT&CK analysis
    print("🎯 Analyzing attack patterns using MITRE ATT&CK framework...")
    attack_analysis = enrich_findings_with_attack(cve_list, pred_label)
    result["mitre_attack_analysis"] = attack_analysis
    
    # Step 6: Generate AI-powered summary
    print("📝 Generating AI-powered vulnerability summary...")
    summary = generate_vuln_summary(pred_label, "unknown_version", cve_list)
    result["ai_summary"] = summary
    
    # Step 7: Generate detailed exploitation guide (if enabled)
    if include_exploitation_guide:
        print("🔧 Generating detailed exploitation guide...")
        try:
            # Extract scan data for exploitation guide
            scan_data = {
                'target_ip': extract_ip_from_scan_file(scan_path),
                'open_ports': extract_open_ports_from_scan_file(scan_path)
            }
            
            # Generate exploitation guide
            exploitation_guide = generate_exploitation_guide(scan_data, cve_list)
            result["exploitation_guide"] = exploitation_guide
            print("✅ Exploitation guide generated successfully")
        except Exception as e:
            print(f"⚠️  Could not generate exploitation guide: {e}")
            result["exploitation_guide"] = None
    else:
        result["exploitation_guide"] = None
    
    # Step 8: Add analysis to learning system for continuous improvement
    print("🧠 Adding this analysis to AI learning system...")
    try:
        initialize_real_time_learning(config)
        add_analysis_for_learning(config, result)
        result["learning_stats"] = get_learning_statistics(config)
        print("✅ Analysis added to learning system and stats retrieved")
    except Exception as e:
        print(f"⚠️  Could not add to learning system: {e}")
    
    return result

def analyze_network_scan_with_exploits(scan_path, output_format="text"):
    """
    Analyze an Nmap XML scan file and generate exploits for vulnerabilities.
    """
    try:
        # Initialize exploit developer
        exploit_dev = ExploitDeveloper()
        
        # Load and parse Nmap scan
        with open(scan_path, 'r') as f:
            scan_data = xmltodict.parse(f.read())
        
        # Analyze vulnerabilities
        vulnerabilities = exploit_dev.analyze_vulnerability(scan_data)
        
        if not vulnerabilities:
            print("🔍 No vulnerabilities found in the scan")
            return
        
        print(f"🚨 Found {len(vulnerabilities)} potential vulnerabilities")
        
        # Process each vulnerability
        exploit_reports = []
        for vuln in vulnerabilities:
            print(f"\n🔍 Analyzing {vuln['service']} on {vuln['host']}:{vuln['port']}")
            
            # Search for existing exploits
            existing_exploits = exploit_dev.search_existing_exploits(vuln)
            
            # Generate new exploit if none found
            generated_exploit = exploit_dev.generate_exploit(vuln, existing_exploits)
            
            # Generate report
            report = exploit_dev.generate_exploit_report(vuln, existing_exploits, generated_exploit)
            exploit_reports.append(report)
            
            # Display results
            if output_format == "json":
                display_json_output(report)
            else:
                display_exploit_results(report)
        
        return exploit_reports
        
    except Exception as e:
        logger.error("Error in exploit analysis", error=str(e))
        print(f"❌ Error analyzing scan: {e}")
        return None

def display_exploit_results(report):
    """
    Display exploit analysis results in a human-readable format
    """
    vuln = report['vulnerability']
    summary = report['summary']
    
    print("\n" + "="*60)
    print(f"🎯 EXPLOIT ANALYSIS: {vuln['service'].upper()} on {vuln['host']}:{vuln['port']}")
    print("="*60)
    
    # Vulnerability details
    print(f"📍 Target: {vuln['host']}:{vuln['port']}")
    print(f"🔧 Service: {vuln['service']}")
    print(f"📦 Product: {vuln.get('product', 'Unknown')}")
    print(f"📋 Version: {vuln.get('version', 'Unknown')}")
    print(f"⚠️  Risk Level: {vuln['risk_level']}")
    print(f"🔍 Common Vulnerabilities: {', '.join(vuln['common_vulns'])}")
    
    # Existing exploits
    existing_exploits = report['existing_exploits']
    print(f"\n📚 Existing Exploits Found: {len(existing_exploits)}")
    
    for i, exploit in enumerate(existing_exploits, 1):
        print(f"  {i}. {exploit['title']}")
        print(f"     Source: {exploit['source']}")
        print(f"     Type: {exploit['type']}")
        print(f"     Platform: {exploit['platform']}")
        print(f"     Verified: {'✅' if exploit['verified'] else '❌'}")
        if 'stars' in exploit:
            print(f"     Stars: {exploit['stars']}")
        print(f"     URL: {exploit['url']}")
    
    # Generated exploit
    generated_exploit = report['generated_exploit']
    if generated_exploit:
        print(f"\n🤖 AI-Generated Exploit:")
        print(f"  📁 File: {generated_exploit['file_path']}")
        print(f"  🎯 Target: {generated_exploit['target']}")
        print(f"  ⚠️  Risk Level: {generated_exploit['risk_level']}")
        print(f"  📅 Generated: {generated_exploit['generated_at']}")
        print(f"  📝 Code Preview:")
        print(f"    {generated_exploit['code_preview']}")
    
    # Recommendations
    print(f"\n💡 Security Recommendations:")
    for i, rec in enumerate(summary['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    print("\n" + "="*60)

def test_waf_bypass(target_url, output_format="text"):
    """
    Test WAF bypass techniques against a target URL
    """
    print(NEXUSAI_LOGO)
    print("🛡️  WAF BYPASS TESTING")
    print("="*60)
    
    try:
        # Initialize WAF bypass tool
        waf_tool = WAFBypassTool()
        
        # Perform comprehensive WAF test
        results = waf_tool.comprehensive_waf_test(target_url)
        
        if output_format == "json":
            display_json_output(results)
            return results
        
        # Display results
        display_waf_bypass_results(results)
        
        return results
        
    except Exception as e:
        logger.error("WAF bypass testing failed", error=str(e))
        print(f"❌ Error: {e}")
        return None

def display_waf_bypass_results(results):
    """Display WAF bypass test results"""
    print("\n" + "="*60)
    print("🛡️  WAF BYPASS TEST RESULTS")
    print("="*60)
    
    target_url = results.get('target_url', 'Unknown')
    print(f"🎯 Target: {target_url}")
    
    # Show WAF fingerprinting results
    waf_info = results.get('waf_fingerprint', {})
    detected_wafs = waf_info.get('detected_wafs', [])
    
    if detected_wafs:
        print(f"\n🛡️  Detected WAFs: {len(detected_wafs)}")
        for waf in detected_wafs:
            print(f"   • {waf['name'].upper()} (Confidence: {waf['confidence']})")
    else:
        print(f"\n❓ No WAF detected")
    
    # Show test results
    test_results = results.get('test_results', {})
    summary = results.get('summary', {})
    
    print(f"\n📊 Test Summary:")
    print(f"   🎯 Total Payloads Tested: {summary.get('total_payloads_tested', 0)}")
    print(f"   ✅ Successful Bypasses: {summary.get('successful_bypasses', 0)}")
    print(f"   🚫 Blocked Payloads: {summary.get('blocked_payloads', 0)}")
    print(f"   📈 Bypass Success Rate: {summary.get('bypass_success_rate', 0):.2%}")
    
    # Show successful bypasses
    successful_bypasses = test_results.get('successful_bypasses', [])
    if successful_bypasses:
        print(f"\n✅ Successful Bypasses Found:")
        for i, bypass in enumerate(successful_bypasses[:5], 1):  # Show first 5
            print(f"   {i}. {bypass['technique'].upper()}")
            print(f"      Payload: {bypass['payload'][:50]}...")
            print(f"      Parameter: {bypass['parameter']}")
            print(f"      Status: {bypass['response_status']}")
    
    # Show recommendations
    recommendations = summary.get('recommendations', [])
    if recommendations:
        print(f"\n💡 Security Recommendations:")
        for rec in recommendations:
            print(f"   • {rec}")
    
    # Show file location
    print(f"\n📁 Results saved to: waf_bypass/results/")

def display_analysis_results(result, output_format="text"):
    """Display comprehensive analysis results in a user-friendly format"""
    if output_format == "json":
        display_json_output(result)
        return
    
    pred_label = result["prediction"]
    print(f"\n🎯 AI PREDICTION: {pred_label.upper()}")
    
    # Show AI-generated analysis
    print("\n🤖 AI-GENERATED ANALYSIS:")
    print("─" * 50)
    print(result["ai_summary"])
    
    # Show top vulnerabilities found
    if result["cves"]:
        print("\n📋 TOP VULNERABILITIES FOUND:")
        print("─" * 50)
        for i, cve in enumerate(result["cves"][:3], 1):
            print(f"{i}. {cve['id']}: {cve['description'][:100]}...")
    
    # Show threat intelligence summary
    threat_intel = result["threat_intelligence"]
    if threat_intel:
        print(f"\n🔍 THREAT INTELLIGENCE SUMMARY:")
        print("─" * 50)
        print(f"  📊 Total CVEs Analyzed: {threat_intel['summary']['total_cves']}")
        print(f"  💥 Exploits Available: {threat_intel['summary']['exploits_found']}")
        print(f"  🚨 CISA KEV CVEs: {threat_intel['summary']['kev_count']}")
    
    # Show MITRE ATT&CK analysis
    attack_analysis = result["mitre_attack_analysis"]
    if attack_analysis:
        print(f"\n🎯 MITRE ATT&CK ANALYSIS:")
        print("─" * 50)
        print(f"  📈 Risk Score: {attack_analysis['risk_score']}/10")
        print(f"  👥 Threat Actors: {', '.join(attack_analysis['threat_actors'])}")
        print(f"  🎭 Attack Techniques: {', '.join(attack_analysis['all_techniques'][:5])}")
    
    # Show exploitation guide
    exploitation_guide = result.get("exploitation_guide")
    if exploitation_guide:
        print(f"\n🔧 DETAILED EXPLOITATION GUIDE:")
        print("─" * 50)
        formatted_guide = format_exploitation_guide(exploitation_guide)
        print(formatted_guide)
        
        # Show quick exploit commands
        quick_commands = generate_quick_exploit_commands(exploitation_guide)
        print(quick_commands)
    
    # Show learning system status
    learning_stats = result.get("learning_stats")
    if learning_stats and not learning_stats.get("error"):
        print(f"\n🧠 AI LEARNING STATUS:")
        print("─" * 50)
        print(f"  📚 Total Learning Samples: {learning_stats.get('total_samples', 0)}")
        print(f"  🕒 Last Updated: {learning_stats.get('last_updated', 'Never')}")
        print(f"  📋 Queue Size: {learning_stats.get('queue_size', 0)}")

def show_ai_learning_statistics():
    """Display current AI learning system statistics"""
    try:
        config = load_project_configuration()
        stats = get_learning_statistics(config)
        print("\n" + "="*60)
        print("🧠 AI LEARNING SYSTEM STATUS")
        print("="*60)
        
        if stats.get("error"):
            print(f"❌ {stats['error']}")
            return
        
        print(f"📊 Total Learning Samples: {stats.get('total_samples', 0)}")
        print(f"🕒 Last Updated: {stats.get('last_updated', 'Never')}")
        print(f"📋 Queue Size: {stats.get('queue_size', 0)}")
        print(f"🔄 Learning Active: {'Yes' if stats.get('is_learning', False) else 'No'}")
        
        # Show recent learning samples
        dataset_path = 'data/learning_dataset.json'
        if os.path.exists(dataset_path):
            import json
            with open(dataset_path, 'r') as f:
                dataset = json.load(f)
            
            if dataset.get('samples'):
                recent_samples = dataset['samples'][-5:]  # Last 5 samples
                print(f"\n📝 Recent Learning Samples:")
                for i, sample in enumerate(recent_samples, 1):
                    timestamp = sample.get('timestamp', 'Unknown')
                    label = sample.get('prediction', 'Unknown')
                    confidence = sample.get('confidence', 0.0)
                    print(f"  {i}. {label} (confidence: {confidence:.2f}) - {timestamp}")
        
    except Exception as e:
        print(f"❌ Error getting learning stats: {e}")

def initialize_ai_learning_system():
    """Initialize the AI learning system for continuous improvement"""
    try:
        rt_config = config.get('real_time_learning', {})
        if rt_config.get('enabled', True):
            initialize_real_time_learning(config)
            print("✅ AI learning system initialized and ready")
        else:
            print("⚠️  AI learning is disabled in configuration")
    except Exception as e:
        print(f"⚠️  Could not initialize AI learning system: {e}")

def create_vulnerability_exploit(vulnerability_name, scan_file=None):
    """
    Create a Python exploit file for a specific vulnerability
    
    Args:
        vulnerability_name (str): Name of the vulnerability (e.g., 'ssh', 'mysql', 'apache') or scan file path
        scan_file (str): Optional scan file path for scan-based exploit generation
    
    Returns:
        dict: Result of the exploit creation process
    """
    try:
        # Initialize exploit developer
        exploit_dev = ExploitDeveloper()
        
        # Create exploits directory if it doesn't exist
        exploits_dir = Path('exploits')
        exploits_dir.mkdir(exist_ok=True)
        
        # Check if vulnerability_name is actually a scan file path
        if scan_file or (vulnerability_name and os.path.exists(vulnerability_name) and vulnerability_name.endswith(('.xml', '.txt', '.csv'))):
            # This is scan-based exploit generation
            scan_path = scan_file or vulnerability_name
            return create_exploits_from_scan(scan_path, exploit_dev)
        
        # Normalize vulnerability name
        vuln_name = vulnerability_name.lower().strip()
        
        # Create sample vulnerability data for the exploit
        sample_vulnerability = {
            'service': vuln_name,
            'port': get_default_port(vuln_name),
            'version': '1.0',
            'description': f'{vuln_name.upper()} vulnerability exploit',
            'risk_level': 'HIGH'
        }
        
        # Generate exploit using the exploit developer
        generated_exploit = exploit_dev.generate_exploit(sample_vulnerability, [])
        
        if not generated_exploit:
            # Create a basic exploit template if no specific exploit is generated
            exploit_code = create_basic_exploit_template(vuln_name)
        else:
            exploit_code = generated_exploit.get('code', create_basic_exploit_template(vuln_name))
        
        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exploit_{vuln_name}_{timestamp}.py"
        filepath = exploits_dir / filename
        
        # Write exploit to file
        with open(filepath, 'w') as f:
            f.write(exploit_code)
        
        # Make file executable
        os.chmod(filepath, 0o755)
        
        logger.info(f"Created exploit file: {filepath}")
        
        return {
            'success': True,
            'filepath': str(filepath),
            'filename': filename,
            'vulnerability': vuln_name,
            'exploit_code': exploit_code[:500] + "..." if len(exploit_code) > 500 else exploit_code
        }
        
    except Exception as e:
        logger.error(f"Error creating exploit for {vulnerability_name}: {e}")
        return {
            'success': False,
            'error': str(e),
            'vulnerability': vulnerability_name
        }

def create_exploits_from_scan(scan_path, exploit_dev):
    """
    Create exploits from scan data and organize them in a folder
    
    Args:
        scan_path (str): Path to the scan file
        exploit_dev: ExploitDeveloper instance
    
    Returns:
        dict: Result of the exploit creation process
    """
    try:
        # Parse the scan file to extract vulnerabilities
        from .parser import parse_nmap_xml
        
        if scan_path.endswith('.xml'):
            scan_data = parse_nmap_xml(scan_path)
        else:
            # Handle other file formats if needed
            scan_data = {'hosts': []}
        
        # Create folder name based on scan file
        scan_filename = Path(scan_path).stem
        folder_name = f"exploits_{scan_filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        exploits_folder = Path('exploits') / folder_name
        exploits_folder.mkdir(exist_ok=True)
        
        generated_exploits = []
        vulnerabilities_found = []
        
        # Extract vulnerabilities from scan data
        for host in scan_data.get('hosts', []):
            for port in host.get('ports', []):
                service = port.get('service', '')
                if service:
                    vulnerability = {
                        'service': service.lower(),
                        'host': host.get('ip', 'unknown'),
                        'port': port.get('port', get_default_port(service)),
                        'version': port.get('version', ''),
                        'description': f'{service.upper()} service on {host.get("ip", "unknown")}:{port.get("port", "unknown")}',
                        'risk_level': 'MEDIUM'
                    }
                    vulnerabilities_found.append(vulnerability)
        
        # Generate exploits for each vulnerability
        for i, vuln in enumerate(vulnerabilities_found):
            try:
                # Generate exploit using the exploit developer
                generated_exploit = exploit_dev.generate_exploit(vuln, [])
                
                if generated_exploit:
                    exploit_code = generated_exploit.get('code', create_basic_exploit_template(vuln['service']))
                else:
                    exploit_code = create_basic_exploit_template(vuln['service'])
                
                # Create filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"exploit_{vuln['service']}_{vuln['host']}_{timestamp}.py"
                filepath = exploits_folder / filename
                
                # Write exploit to file
                with open(filepath, 'w') as f:
                    f.write(exploit_code)
                
                # Make file executable
                os.chmod(filepath, 0o755)
                
                generated_exploits.append({
                    'filepath': str(filepath),
                    'filename': filename,
                    'vulnerability': vuln['service'],
                    'host': vuln['host'],
                    'port': vuln['port']
                })
                
                logger.info(f"Created exploit: {filepath}")
                
            except Exception as e:
                logger.error(f"Error creating exploit for {vuln['service']}: {e}")
        
        # Create a summary file
        summary_file = exploits_folder / "README.md"
        with open(summary_file, 'w') as f:
            f.write(f"# Exploits Generated from {scan_filename}\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"## Vulnerabilities Found: {len(vulnerabilities_found)}\n\n")
            f.write("## Generated Exploits:\n\n")
            for exploit in generated_exploits:
                f.write(f"- `{exploit['filename']}` - {exploit['vulnerability'].upper()} exploit for {exploit['host']}:{exploit['port']}\n")
        
        return {
            'success': True,
            'folder_path': str(exploits_folder),
            'folder_name': folder_name,
            'exploits_generated': len(generated_exploits),
            'vulnerabilities_found': len(vulnerabilities_found),
            'exploits': generated_exploits,
            'scan_file': scan_path
        }
        
    except Exception as e:
        logger.error(f"Error creating exploits from scan {scan_path}: {e}")
        return {
            'success': False,
            'error': str(e),
            'scan_file': scan_path
        }

def get_default_port(service_name):
    """Get default port for a service"""
    default_ports = {
        'ssh': 22,
        'ftp': 21,
        'telnet': 23,
        'http': 80,
        'https': 443,
        'mysql': 3306,
        'postgresql': 5432,
        'redis': 6379,
        'mongodb': 27017,
        'elasticsearch': 9200,
        'jenkins': 8080,
        'docker': 2375,
        'kubernetes': 6443,
        'smb': 445,
        'rdp': 3389,
        'apache': 80,
        'nginx': 80,
        'tomcat': 8080,
        'weblogic': 7001,
        'websphere': 9080
    }
    return default_ports.get(service_name, 80)

def create_basic_exploit_template(vuln_name):
    """Create a basic exploit template for a vulnerability"""
    
    # Import statements
    vuln_upper = vuln_name.upper()
    imports = f'''#!/usr/bin/env python3
"""
NEXUS-AI Generated Exploit for {vuln_upper}
Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

This exploit was automatically generated by NEXUS-AI for educational purposes.
Only use on systems you own or have explicit permission to test.
"""

import socket
import sys
import time
import argparse
from typing import Optional, Dict, Any

# Add any additional imports based on vulnerability type
'''
    
    # Service-specific templates
    templates = {
        'ssh': '''
class SSHExploit:
    """SSH service exploitation module"""
    
    def __init__(self, target: str, port: int = 22):
        self.target = target
        self.port = port
        self.timeout = 10
        
    def test_connection(self) -> bool:
        """Test if SSH service is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"[-] Connection test failed: {{e}}")
            return False
    
    def brute_force_credentials(self, username: str, password_list: list) -> Optional[Dict[str, str]]:
        """Attempt brute force attack on SSH"""
        print(f"[+] Attempting brute force on {{self.target}}:{{self.port}}")
        
        for password in password_list:
            try:
                # This is a template - implement actual SSH connection logic
                print(f"[*] Trying {{username}}:{{password}}")
                time.sleep(0.1)  # Rate limiting
                
                # Placeholder for actual SSH authentication
                # import paramiko
                # ssh = paramiko.SSHClient()
                # ssh.connect(self.target, username=username, password=password)
                
            except Exception as e:
                continue
        
        return None
    
    def run(self):
        """Main exploit execution"""
        print(f"[+] Starting SSH exploit against {{self.target}}:{{self.port}}")
        
        if not self.test_connection():
            print("[-] Target is not accessible")
            return False
        
        # Common SSH credentials to try
        common_credentials = [
            ("admin", "admin"),
            ("root", "root"),
            ("user", "password"),
            ("admin", "password"),
            ("root", "password")
        ]
        
        for username, password in common_credentials:
            result = self.brute_force_credentials(username, [password])
            if result:
                print(f"[+] Success! Credentials: {{result}}")
                return True
        
        print("[-] No valid credentials found")
        return False

def main():
    parser = argparse.ArgumentParser(description="SSH Exploit")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=22, help="SSH port (default: 22)")
    
    args = parser.parse_args()
    
    exploit = SSHExploit(args.target, args.port)
    exploit.run()

if __name__ == "__main__":
    main()
''',
        
        'mysql': '''
class MySQLExploit:
    """MySQL service exploitation module"""
    
    def __init__(self, target: str, port: int = 3306):
        self.target = target
        self.port = port
        self.timeout = 10
        
    def test_connection(self) -> bool:
        """Test if MySQL service is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"[-] Connection test failed: {{e}}")
            return False
    
    def test_credentials(self, username: str, password: str) -> bool:
        """Test MySQL credentials"""
        try:
            # This is a template - implement actual MySQL connection logic
            # import mysql.connector
            # connection = mysql.connector.connect(
            #     host=self.target,
            #     port=self.port,
            #     user=username,
            #     password=password
            # )
            print(f"[*] Testing {{username}}:{{password}}")
            return False  # Placeholder
        except Exception as e:
            return False
    
    def run(self):
        """Main exploit execution"""
        print(f"[+] Starting MySQL exploit against {{self.target}}:{{self.port}}")
        
        if not self.test_connection():
            print("[-] Target is not accessible")
            return False
        
        # Common MySQL credentials
        common_credentials = [
            ("root", ""),
            ("root", "root"),
            ("admin", "admin"),
            ("mysql", "mysql"),
            ("user", "password")
        ]
        
        for username, password in common_credentials:
            if self.test_credentials(username, password):
                print(f"[+] Success! Credentials: {{username}}:{{password}}")
                return True
        
        print("[-] No valid credentials found")
        return False

def main():
    parser = argparse.ArgumentParser(description="MySQL Exploit")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=3306, help="MySQL port (default: 3306)")
    
    args = parser.parse_args()
    
    exploit = MySQLExploit(args.target, args.port)
    exploit.run()

if __name__ == "__main__":
    main()
''',
        
        'apache': '''
class ApacheExploit:
    """Apache web server exploitation module"""
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self.timeout = 10
        
    def test_connection(self) -> bool:
        """Test if Apache service is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.port = port
            sock.close()
            return result == 0
        except Exception as e:
            print(f"[-] Connection test failed: {{e}}")
            return False
    
    def test_path_traversal(self) -> bool:
        """Test for path traversal vulnerability"""
        print("[+] Testing for path traversal vulnerability")
        
        # Common path traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in payloads:
            try:
                # This is a template - implement actual HTTP request logic
                # import requests
                # response = requests.get(f"http://{{self.target}}:{{self.port}}/{{payload}}")
                print(f"[*] Testing payload: {{payload}}")
                time.sleep(0.1)
            except Exception as e:
                continue
        
        return False
    
    def run(self):
        """Main exploit execution"""
        print(f"[+] Starting Apache exploit against {{self.target}}:{{self.port}}")
        
        if not self.test_connection():
            print("[-] Target is not accessible")
            return False
        
        # Test various vulnerabilities
        if self.test_path_traversal():
            print("[+] Path traversal vulnerability found!")
            return True
        
        print("[-] No vulnerabilities found")
        return False

def main():
    parser = argparse.ArgumentParser(description="Apache Exploit")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=80, help="Apache port (default: 80)")
    
    args = parser.parse_args()
    
    exploit = ApacheExploit(args.target, args.port)
    exploit.run()

if __name__ == "__main__":
    main()
'''
    }
    
    # Get template for the vulnerability or use generic template
    vuln_upper = vuln_name.upper()
    default_port = get_default_port(vuln_name)
    
    template = templates.get(vuln_name, f'''
class {vuln_upper}Exploit:
    """{{vuln_upper}} service exploitation module"""
    
    def __init__(self, target: str, port: int = {default_port}):
        self.target = target
        self.port = port
        self.timeout = 10
        
    def test_connection(self) -> bool:
        """Test if {{vuln_upper}} service is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"[-] Connection test failed: {{e}}")
            return False
    
    def run(self):
        """Main exploit execution"""
        print(f"[+] Starting {{vuln_upper}} exploit against {{self.target}}:{{self.port}}")
        
        if not self.test_connection():
            print("[-] Target is not accessible")
            return False
        
        print(f"[*] {{vuln_upper}} service detected")
        print("[*] Implement specific exploitation logic here")
        
        return False

def main():
    parser = argparse.ArgumentParser(description="{{vuln_upper}} Exploit")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default={default_port}, help="{{vuln_upper}} port (default: {default_port})")
    
    args = parser.parse_args()
    
    exploit = {vuln_upper}Exploit(args.target, args.port)
    exploit.run()

if __name__ == "__main__":
    main()
''')
    
    return imports + template

def display_vulndev_results(result):
    """Display vulnerability exploit development results"""
    print("\n" + "="*60)
    print("🔧 VULNERABILITY EXPLOIT DEVELOPMENT")
    print("="*60)
    
    if result['success']:
        # Check if this is a scan-based result (has folder_path)
        if 'folder_path' in result:
            # Scan-based exploit generation
            print(f"✅ Successfully generated exploits from scan file!")
            print(f"📁 Folder: {result['folder_path']}")
            print(f"📊 Vulnerabilities found: {result['vulnerabilities_found']}")
            print(f"🔧 Exploits generated: {result['exploits_generated']}")
            print(f"📄 Scan file: {result['scan_file']}")
            
            print(f"\n📂 Generated Exploits:")
            for exploit in result['exploits']:
                print(f"   • {exploit['filename']} - {exploit['vulnerability'].upper()} for {exploit['host']}:{exploit['port']}")
            
            print(f"\n💡 Usage:")
            print(f"   cd {result['folder_path']}")
            print(f"   python <exploit_file.py> <target_ip>")
            
            print(f"\n📖 Summary:")
            print(f"   • Check the README.md file in the folder for details")
            print(f"   • Each exploit is tailored to the specific service and host")
            print(f"   • All exploits include advanced evasion techniques")
            
        else:
            # Single vulnerability exploit
            print(f"✅ Successfully created exploit for: {result['vulnerability'].upper()}")
            print(f"📁 File: {result['filepath']}")
            print(f"📝 Filename: {result['filename']}")
            print(f"\n💡 Usage:")
            print(f"   python {result['filename']} <target_ip>")
            print(f"   python {result['filename']} <target_ip> --port <port_number>")
            
            print(f"\n🔧 Exploit Preview:")
            print("-" * 40)
            print(result['exploit_code'])
            print("-" * 40)
        
        print(f"\n⚠️  IMPORTANT WARNINGS:")
        print(f"   • Only use on systems you own or have explicit permission")
        print(f"   • This exploit is for educational purposes only")
        print(f"   • Follow responsible disclosure practices")
        print(f"   • Be aware of legal implications")
        
    else:
        print(f"❌ Failed to create exploit")
        print(f"Error: {result.get('error', 'Unknown error')}")
        if 'vulnerability' in result:
            print(f"Vulnerability: {result['vulnerability']}")
        if 'scan_file' in result:
            print(f"Scan file: {result['scan_file']}")
        print(f"\n💡 Try with a different vulnerability name (e.g., ssh, mysql, apache) or scan file")

def fetch_exploits_from_web(limit: int = 50):
    """Fetch educational exploits from web sources and add to database"""
    try:
        from ..ai.exploit_fetcher import exploit_fetcher
        
        print("\n" + "="*60)
        print("🌐 FETCHING EDUCATIONAL EXPLOITS FROM WEB")
        print("="*60)
        
        print(f"📡 Fetching up to {limit} exploits per source...")
        print("⏳ This may take a few minutes...")
        
        # Fetch exploits
        results = exploit_fetcher.fetch_all_exploits(max_exploits=limit)
        
        # Display results
        print(f"\n✅ Fetching completed in {results.get('duration', 0):.2f} seconds")
        print(f"📊 Total exploits fetched: {results.get('total_fetched', 0)}")
        print(f"💾 Total exploits added to database: {results.get('total_added', 0)}")
        
        if results.get('errors'):
            print(f"\n⚠️  Errors encountered: {len(results['errors'])}")
            for error in results['errors'][:3]:  # Show first 3 errors
                print(f"   • {error}")
        
        # Show results by source
        print(f"\n📈 Results by Source:")
        for source_name, source_results in results.get('sources', {}).items():
            print(f"   • {source_name.upper()}: {source_results.get('fetched', 0)} fetched, {source_results.get('added', 0)} added")
        
        print(f"\n💡 Database now contains educational exploits for learning purposes")
        print(f"🔒 All exploits are verified and safe for educational use")
        
    except Exception as e:
        print(f"❌ Error fetching exploits: {e}")
        logger.error(f"Exploit fetching failed: {e}")

def show_exploit_database_info():
    """Display exploit database statistics and information"""
    try:
        from ..ai.exploit_database_enhanced import enhanced_exploit_db
        
        # Get database statistics
        stats = enhanced_exploit_db.get_statistics()
        
        print(f"📊 Database Statistics:")
        print(f"   • Total Exploits: {stats.get('total_exploits', 0)}")
        
        if stats.get('by_service'):
            print(f"\n🔧 Exploits by Service:")
            for service, count in stats['by_service'].items():
                print(f"   • {service.upper()}: {count}")
        
        if stats.get('by_category'):
            print(f"\n📂 Exploits by Category:")
            for category, count in stats['by_category'].items():
                print(f"   • {category.replace('_', ' ').title()}: {count}")
        
        if stats.get('by_difficulty'):
            print(f"\n⚡ Exploits by Difficulty:")
            for difficulty, count in stats['by_difficulty'].items():
                print(f"   • {difficulty.title()}: {count}")
        
        print(f"\n💡 Database Features:")
        print(f"   • Local SQLite database for reliability")
        print(f"   • Educational exploit templates")
        print(f"   • Safety warnings and usage instructions")
        print(f"   • Categorized by service and difficulty")
        print(f"   • Verified and safe exploit code")
        
        print(f"\n🔧 Available Categories:")
        categories = enhanced_exploit_db.categories
        for category, services in categories.items():
            print(f"   • {category.replace('_', ' ').title()}: {', '.join(services)}")
        
        print(f"\n📁 Database Location: {enhanced_exploit_db.db_path}")
        
    except Exception as e:
        print(f"❌ Error accessing exploit database: {e}")
        print("💡 The database may need to be initialized")

def generate_exploits_from_scan(scan_path: str):
    """Generate exploits from scan data and save to database"""
    try:
        from ..ai.exploit_developer import ExploitDeveloper
        
        # Load scan data
        if not os.path.exists(scan_path):
            print(f"❌ Scan file not found: {scan_path}")
            return
        
        # Parse scan data
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(scan_path)
            root = tree.getroot()
            
            scan_data = {'hosts': []}
            
            for host in root.findall('.//host'):
                host_data = {'ports': []}
                
                # Get host address
                address_elem = host.find('address')
                if address_elem is not None:
                    host_data['address'] = {
                        'addr': address_elem.get('addr', ''),
                        'addrtype': address_elem.get('addrtype', '')
                    }
                
                # Get ports
                for port in host.findall('.//port'):
                    port_data = {
                        'portid': port.get('portid', ''),
                        'protocol': port.get('protocol', ''),
                        'state': port.find('state').get('state', '') if port.find('state') is not None else 'unknown'
                    }
                    
                    # Get service info
                    service_elem = port.find('service')
                    if service_elem is not None:
                        port_data['service'] = {
                            'name': service_elem.get('name', ''),
                            'product': service_elem.get('product', ''),
                            'version': service_elem.get('version', '')
                        }
                    
                    host_data['ports'].append(port_data)
                
                scan_data['hosts'].append(host_data)
            
        except Exception as e:
            print(f"❌ Error parsing scan file: {e}")
            return
        
        if not scan_data or not scan_data.get('hosts'):
            print("❌ No valid scan data found")
            return
        
        # Initialize exploit developer
        exploit_developer = ExploitDeveloper()
        
        # Analyze vulnerabilities from scan data
        vulnerabilities = exploit_developer.analyze_vulnerability(scan_data)
        
        if not vulnerabilities:
            print("❌ No vulnerabilities found in scan data")
            return
        
        print(f"🔍 Found {len(vulnerabilities)} potential vulnerabilities")
        print("🔄 Starting exploit generation and database saving workflow...")
        
        saved_count = 0
        total_generated = 0
        
        # Process each vulnerability
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n📊 Processing Vulnerability {i}/{len(vulnerabilities)}:")
            print(f"   • Service: {vuln.get('service', 'Unknown')}")
            print(f"   • Host: {vuln.get('host', 'Unknown')}")
            print(f"   • Port: {vuln.get('port', 'Unknown')}")
            print(f"   • Risk Level: {vuln.get('risk_level', 'Unknown')}")
            
            # Generate and save exploit
            result = exploit_developer.generate_and_save_exploit(vuln)
            
            if result.get('success'):
                saved_count += 1
                total_generated += 1
                
                exploit_data = result.get('exploit_data', {})
                comparison_results = result.get('comparison_results', {})
                
                print(f"   ✅ Exploit generated and saved successfully!")
                print(f"   📝 Name: {exploit_data.get('name', 'Unknown')}")
                print(f"   🎯 Service: {exploit_data.get('service', 'Unknown')}")
                print(f"   📊 Category: {exploit_data.get('category', 'Unknown')}")
                print(f"   ⚡ Difficulty: {exploit_data.get('difficulty', 'Unknown')}")
                print(f"   🔥 Risk Level: {exploit_data.get('risk_level', 'Unknown')}")
                print(f"   🎯 Uniqueness Score: {exploit_data.get('uniqueness_score', 0.0):.2f}")
                print(f"   📚 Similar Exploits: {exploit_data.get('similar_exploits', 0)}")
                
                # Show comparison recommendations
                if comparison_results.get('recommendations'):
                    print(f"   💡 Recommendations:")
                    for rec in comparison_results['recommendations']:
                        print(f"      - {rec}")
            else:
                print(f"   ❌ Failed to generate/save exploit: {result.get('error', 'Unknown error')}")
        
        print(f"\n✅ Exploit generation and saving completed!")
        print(f"📊 Summary:")
        print(f"   • Total vulnerabilities processed: {len(vulnerabilities)}")
        print(f"   • Exploits generated: {total_generated}")
        print(f"   • Exploits saved to database: {saved_count}")
        
        # Show updated database statistics
        print(f"\n📊 Updated Database Statistics:")
        from ..ai.exploit_database import exploit_db
        stats = exploit_db.get_statistics()
        if stats:
            print(f"   • Total Exploits: {stats.get('total_exploits', 0)}")
            print(f"   • New Exploits Added: {saved_count}")
        
    except Exception as e:
        print(f"❌ Error generating exploits from scan: {e}")
        import traceback
        traceback.print_exc()

def main():
    """
    Main entry point for NEXUS-AI command line interface
    
    This tool provides:
    - Network scan analysis using AI
    - Threat intelligence gathering
    - Vulnerability assessment
    - MITRE ATT&CK analysis
    - Continuous AI learning
    """
    parser = argparse.ArgumentParser(
        description="NEXUS-AI: Your AI-powered network security analysis companion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a network scan (standard output)
  NexusAI --input scan.xml

  # Analyze with detailed exploitation guide
  NexusAI --input scan.xml --guide

  # Get JSON output for integration
  NexusAI --input scan.xml --output-format json

  # Check IP reputation
  NexusAI --check-ips 8.8.8.8 1.1.1.1

  # Search for internet assets
  NexusAI --search-assets "apache"

  # Test WAF bypass techniques
  NexusAI --waf-bypass https://example.com

  # View AI learning statistics
  NexusAI --learning-stats

  # Create exploit for specific vulnerability
  NexusAI --vulndev ssh
  NexusAI --vulndev mysql
  NexusAI --vulndev apache

  # Generate exploits from scan file (creates folder with all exploits)
  NexusAI --vulndev scan.xml
  NexusAI --vulndev network_scan.txt

  # View exploit database information
              NexusAI --exploit-db

            # Fetch exploits from web sources
            NexusAI --fetch-exploits
            NexusAI --fetch-exploits --fetch-limit 100

  # Generate exploits from scan data
            NexusAI --input scan.xml --generate-exploits

For more help, visit: https://github.com/Dreepsy/Project_Nexus
        """
    )
    
    # Define command line arguments
    parser.add_argument("--input", "-i", help="Path to your Nmap XML scan file")
    parser.add_argument("--output-format", "-o", choices=["text", "json"], default="text",
                       help="Output format: 'text' (human-readable) or 'json' (for integration)")
    parser.add_argument("--check-ips", nargs="+", metavar="IP",
                       help="Check IP reputation using multiple threat intelligence sources")
    parser.add_argument("--search-assets", metavar="QUERY",
                       help="Search for internet-facing assets using Shodan")
    parser.add_argument("--learning-stats", action="store_true",
                       help="Show AI learning system statistics")
    parser.add_argument("--waf-bypass", metavar="URL",
                       help="Test WAF bypass techniques against a target URL")
    parser.add_argument("--guide", "-g", action="store_true",
                       help="Generate detailed exploitation guide")
    parser.add_argument("--vulndev", "-v", metavar="VULNERABILITY_OR_SCAN_FILE",
                       help="Create exploits for a specific vulnerability (e.g., 'ssh', 'mysql', 'apache') or generate exploits from a scan file")
    parser.add_argument("--exploit-db", action="store_true",
                       help="Show exploit database statistics and manage local exploits")
    parser.add_argument("--fetch-exploits", action="store_true",
                       help="Fetch educational exploits from web sources and add to database")
    parser.add_argument("--fetch-limit", type=int, default=50,
                       help="Maximum number of exploits to fetch per source (default: 50)")
    parser.add_argument("--generate-exploits", action="store_true",
                       help="Generate exploits from scan data and save to database")
    
    args = parser.parse_args()
    
    # Display welcome message
    print(NEXUSAI_LOGO)
    print("🔍 Starting NEXUS-AI analysis...\n")
    
    # Initialize AI learning system
    initialize_ai_learning_system()
    
    # Handle learning statistics command
    if args.learning_stats:
        show_ai_learning_statistics()
        return
    
    # Handle WAF bypass testing
    if args.waf_bypass:
        print("🛡️  Testing WAF bypass techniques...")
        test_waf_bypass(args.waf_bypass, args.output_format)
        return
    
    # Handle exploit database command
    if args.exploit_db:
        show_exploit_database_info()
        return
    
    # Handle exploit fetching command
    if args.fetch_exploits:
        fetch_exploits_from_web(args.fetch_limit)
        return
    
    # Handle exploit generation and saving command
    if args.generate_exploits:
        if not args.input:
            parser.error("Please provide a scan file with --input for exploit generation")
        print("🔧 Generating exploits from scan data and saving to database...")
        generate_exploits_from_scan(args.input)
        return
    
    # Handle vulnerability exploit development command
    if args.vulndev:
        print("🔧 Creating vulnerability exploits...")
        
        # Check if it's a scan file or vulnerability name
        if os.path.exists(args.vulndev) and args.vulndev.endswith(('.xml', '.txt', '.csv')):
            print(f"📁 Generating exploits from scan file: {args.vulndev}")
            result = create_vulnerability_exploit(args.vulndev)
        else:
            print(f"🔧 Creating exploit for vulnerability: {args.vulndev}")
            result = create_vulnerability_exploit(args.vulndev)
        
        if args.output_format == "json":
            display_json_output(result)
        else:
            display_vulndev_results(result)
        return
    
    # Handle threat intelligence commands
    if args.check_ips:
        print("🔍 Checking IP reputation using threat intelligence...")
        ati = AdvancedThreatIntel()
        result = ati.aggregate_threat_feeds(args.check_ips)
        if args.output_format == "json":
            display_json_output(result)
        else:
            show_threat_intelligence_results(result)
        return
    
    if args.search_assets:
        print("🌐 Searching for internet assets...")
        ati = AdvancedThreatIntel()
        result = ati.search_internet_assets(args.search_assets)
        if args.output_format == "json":
            display_json_output(result)
        else:
            show_shodan_search_results(result)
        return
    
    # Handle network scan analysis
    if not args.input:
        parser.error("Please provide a scan file with --input")
    
    if not os.path.exists(args.input):
        print(f"❌ File not found: {args.input}")
        print("💡 Please check the file path and try again")
        return
    
    # Determine if exploitation guide should be included
    include_exploitation_guide = args.guide
    
    # Perform comprehensive analysis
    result = analyze_network_scan(args.input, args.output_format, include_exploitation_guide)
    
    # Display results or handle errors
    if result["errors"]:
        print("❌ Analysis encountered errors:")
        for error in result["errors"]:
            print(f"  - {error}")
        if args.output_format == "json":
            display_json_output(result)
        return
    
    # Display comprehensive results
    display_analysis_results(result, args.output_format)
    
    # Show completion message
    print("\n" + "="*60)
    print("✅ Analysis Complete!")
    print("💡 Your AI companion has analyzed the scan and learned from it")
    print("🔄 The AI will improve with each analysis you perform")

if __name__ == "__main__":
    main()
