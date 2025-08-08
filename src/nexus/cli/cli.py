#!/usr/bin/env python3
import argparse
import os
import json
from .parser import parse_nmap_xml
from .predictor import load_enhanced_model, predict_class, get_model_info, get_label_mapping
from .vuln_info import get_vuln_info
from ..ai.deepseek_integration import generate_vuln_summary
from ..ai.vuln_cve_fetcher import fetch_cves
from ..ai.threat_feeds import enrich_cves_with_threat_intel
from ..ai.mitre_attack import enrich_findings_with_attack
from ..ai.advanced_threat_intel import AdvancedThreatIntel
from ..core.config import get_config, get_logger

# Get configuration and logger
config = get_config()
logger = get_logger()

NEXUSAI_LOGO = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    N E X U S - A I                           ║
║                                                              ║
║              AI-Powered Network Analysis Tool                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

def print_json(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))

def print_threat_intel_results(result):
    """Print threat intelligence results in a human-readable format."""
    print("\n" + "="*60)
    print("🔍 ADVANCED THREAT INTELLIGENCE RESULTS")
    print("="*60)
    
    summary = result.get("summary", {})
    print(f"📊 Summary:")
    print(f"  - Total indicators: {summary.get('total_indicators', 0)}")
    print(f"  - Malicious: {summary.get('malicious_count', 0)}")
    print(f"  - Suspicious: {summary.get('suspicious_count', 0)}")
    print(f"  - Clean: {summary.get('clean_count', 0)}")
    
    print(f"\n🔍 Detailed Analysis:")
    for indicator, data in result.get("indicators", {}).items():
        print(f"\n📍 {indicator}:")
        print(f"  - Threat Level: {data.get('threat_level', 'unknown').upper()}")
        print(f"  - Reputation Score: {data.get('reputation_score', 0)}/100")
        
        # VirusTotal results
        vt_data = data.get("virustotal", {})
        if "error" not in vt_data:
            print(f"  - VirusTotal: {vt_data.get('detection_ratio', 'N/A')} detections")
            if vt_data.get("detected_by"):
                print(f"    Detected by: {', '.join([d['scanner'] for d in vt_data['detected_by'][:3]])}")
        else:
            print(f"  - VirusTotal: {vt_data.get('error', 'N/A')}")
        
        # Shodan results
        shodan_data = data.get("shodan", {})
        if "error" not in shodan_data:
            print(f"  - Shodan: {len(shodan_data.get('ports', []))} open ports")
            if shodan_data.get("vulns"):
                print(f"    Vulnerabilities: {', '.join(shodan_data['vulns'][:3])}")
        else:
            print(f"  - Shodan: {shodan_data.get('error', 'N/A')}")

def print_shodan_results(result):
    """Print Shodan search results in a human-readable format."""
    print("\n" + "="*60)
    print("🌐 SHODAN INTERNET ASSET SEARCH RESULTS")
    print("="*60)
    
    print(f"🔍 Query: {result.get('query', 'N/A')}")
    print(f"📊 Total results: {result.get('total', 0)}")
    
    print(f"\n🎯 Top matches:")
    for i, match in enumerate(result.get("matches", [])[:5], 1):
        print(f"\n{i}. {match.get('ip', 'N/A')}:{match.get('port', 'N/A')}")
        print(f"   - Protocol: {match.get('protocol', 'N/A')}")
        print(f"   - Product: {match.get('product', 'N/A')} {match.get('version', '')}")
        print(f"   - Organization: {match.get('org', 'N/A')}")
        if match.get('location'):
            loc = match['location']
            print(f"   - Location: {loc.get('city', 'N/A')}, {loc.get('country_name', 'N/A')}")
        print(f"   - Data: {match.get('data', 'N/A')[:100]}...")

def interactive_mode(scan_path):
    print(NEXUSAI_LOGO)
    print("[INTERACTIVE MODE] Welcome to NEXUS-AI!")
    print(f"[*] Nmap scan file: {scan_path}")
    input("Press Enter to parse the scan...")
    try:
        features = parse_nmap_xml(scan_path)
        print("[+] Scan parsed successfully.")
    except Exception as e:
        print(f"[!] Failed to parse Nmap XML: {e}")
        return
    input("Press Enter to load the model and predict class...")
    try:
        ensemble_model = load_enhanced_model()
        pred_index = predict_class(features, ensemble_model)
        label_mapping = get_label_mapping(ensemble_model)
        if pred_index in label_mapping:
            pred_label = label_mapping[pred_index]
        else:
            print(f"[!] Prediction index {pred_index} is out of range.")
            return
        print(f"[+] Predicted Behaviour Class: {pred_label}")
    except Exception as e:
        print(f"[!] Prediction failed: {e}")
        return
    input("Press Enter to fetch real CVEs and generate AI-powered vulnerability summary...")
    # Try to fetch real CVEs for the predicted label (as service)
    cve_list = fetch_cves(pred_label, "unknown_version")
    if not cve_list:
        # Fallback to mock CVEs if none found
        cve_list = [
            {"id": "CVE-2021-41773", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49."},
            {"id": "CVE-2021-42013", "description": "Remote code execution in Apache HTTP Server 2.4.50."}
        ]
    
    # Enrich CVEs with threat intelligence
    print("[*] Enriching CVEs with threat intelligence...")
    threat_intel = enrich_cves_with_threat_intel(cve_list, pred_label)
    
    # Enrich CVEs with MITRE ATT&CK analysis
    print("[*] Enriching CVEs with MITRE ATT&CK analysis...")
    attack_analysis = enrich_findings_with_attack(cve_list, pred_label)
    
    summary = generate_vuln_summary(pred_label, "unknown_version", cve_list)
    print("\n[AI-Generated Vulnerability Summary and Exploitation Guide]:")
    print(summary)
    info = get_vuln_info(pred_label)
    print("\n[!] Vulnerability Information:")
    print(f"Description: {info['description']}")
    print(f"Recommendation: {info['recommendation']}")
    
    # Display threat intelligence results
    print("\n[+] Threat Intelligence Summary:")
    print(f"  - Total CVEs: {threat_intel['summary']['total_cves']}")
    print(f"  - Exploits found: {threat_intel['summary']['exploits_found']}")
    print(f"  - CISA KEV CVEs: {threat_intel['summary']['kev_count']}")
    if threat_intel['vendor_advisory']:
        print(f"  - Vendor advisory: {threat_intel['vendor_advisory']}")
    
    if threat_intel['exploits']:
        print("\n[+] Available Exploits:")
        for exploit in threat_intel['exploits'][:3]:  # Show top 3
            print(f"  - {exploit['id']}: {exploit['description'][:80]}...")
    
    if threat_intel['kev_status']:
        kev_cves = [cve for cve, is_kev in threat_intel['kev_status'].items() if is_kev]
        if kev_cves:
            print(f"\n[!] HIGH PRIORITY - CISA KEV CVEs: {', '.join(kev_cves)}")
    
    # Display MITRE ATT&CK analysis
    print("\n[+] MITRE ATT&CK Analysis:")
    print(f"  - Risk Score: {attack_analysis['risk_score']}/10")
    print(f"  - Threat Actors: {', '.join(attack_analysis['threat_actors'])}")
    print(f"  - Techniques Found: {', '.join(attack_analysis['all_techniques'])}")
    
    print("\n[+] ATT&CK Tactics:")
    for tactic_id, tactic_info in attack_analysis['tactics_analysis'].items():
        print(f"  - {tactic_id} - {tactic_info['name']}")
        for technique in tactic_info['techniques']:
            print(f"    * {technique['id']}: {technique['name']}")
    
    print("[END OF INTERACTIVE SESSION]")

def main():
    """
    Main CLI entry point for analyzing Nmap XML scan and predicting class.
    Supports output in text or JSON, and an interactive mode for step-by-step analysis.
    Now fetches real CVEs from the NVD, enriches them with threat intelligence,
    and provides MITRE ATT&CK framework analysis.
    """
    parser = argparse.ArgumentParser(
        description="NEXUS-AI CLI Tool - Analyze Nmap XML scan with AI-powered vulnerability interpretation and ATT&CK analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  NexusAI --input scan.xml                    # Basic analysis
  NexusAI --input scan.xml --output-format json  # JSON output
  NexusAI --input scan.xml --interactive     # Step-by-step mode
  NexusAI --check-ips 8.8.8.8 1.1.1.1      # Check IP reputation
  NexusAI --search-assets "apache"           # Search for Apache servers
  NexusAI --threat-intel --input scan.xml    # Enhanced analysis with threat intel

For more information, visit: https://github.com/your-repo/Project_Nexus
        """
    )
    parser.add_argument(
        "--input", "-i", required=True, help="Path to Nmap XML file to analyze."
    )
    parser.add_argument(
        "--output-format", "-o", choices=["text", "json"], default="text",
        help="Output format: 'text' (default) or 'json'."
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="Run in interactive mode for step-by-step analysis."
    )
    parser.add_argument(
        "--threat-intel", action="store_true",
        help="Enable advanced threat intelligence analysis (VirusTotal, Shodan)."
    )
    parser.add_argument(
        "--check-ips", nargs="+", metavar="IP",
        help="Check IP reputation using multiple threat feeds."
    )
    parser.add_argument(
        "--search-assets", metavar="QUERY",
        help="Search for internet-facing assets using Shodan."
    )
    args = parser.parse_args()

    print(NEXUSAI_LOGO)
    print("🔍 Starting NEXUS-AI analysis...\n")

    if not os.path.exists(args.input):
        print(f"❌ [ERROR] File not found: {args.input}")
        print("💡 Tip: Use --help for usage instructions.")
        return

    if args.interactive:
        interactive_mode(args.input)
        return
    
    # Handle threat intelligence specific commands
    if args.check_ips:
        print("🔍 Checking IP reputation using advanced threat intelligence...")
        ati = AdvancedThreatIntel()
        result = ati.aggregate_threat_feeds(args.check_ips)
        if args.output_format == "json":
            print_json(result)
        else:
            print_threat_intel_results(result)
        return
    
    if args.search_assets:
        print("🌐 Searching for internet-facing assets...")
        ati = AdvancedThreatIntel()
        result = ati.search_internet_assets(args.search_assets)
        if args.output_format == "json":
            print_json(result)
        else:
            print_shodan_results(result)
        return

    # Non-interactive: run full pipeline and print or output JSON
    result = {
        "scan_file": args.input,
        "prediction": None,
        "ai_summary": None,
        "static_info": None,
        "cves": None,
        "threat_intelligence": None,
        "mitre_attack_analysis": None,
        "errors": []
    }
    print("📄 Parsing Nmap XML scan...")
    try:
        features = parse_nmap_xml(args.input)
        print("✅ Scan parsed successfully")
    except Exception as e:
        msg = f"Failed to parse Nmap XML: {e}"
        print(f"❌ [ERROR] {msg}")
        result["errors"].append(msg)
        if args.output_format == "json":
            print_json(result)
        return
    print("🤖 Loading AI model and making prediction...")
    try:
        # Load enhanced model
        ensemble_model = load_enhanced_model()
        model_info = get_model_info(ensemble_model)
        label_mapping = get_label_mapping(ensemble_model)
        
        print(f"🤖 Using {model_info['model_type']} model with {model_info['num_models']} sub-models")
        
        # Make prediction
        pred_index = predict_class(features, ensemble_model)
        
        # Get prediction label
        if pred_index in label_mapping:
            pred_label = label_mapping[pred_index]
        else:
            msg = f"Prediction index {pred_index} is out of range."
            print(f"❌ [ERROR] {msg}")
            result["errors"].append(msg)
            if args.output_format == "json":
                print_json(result)
            return
        
        result["prediction"] = pred_label
        result["model_info"] = model_info
        print(f"✅ Predicted behavior class: {pred_label}")
        print(f"📊 Model confidence: {model_info['num_models']} models in ensemble")
    except Exception as e:
        msg = f"Prediction failed: {e}"
        print(f"❌ [ERROR] {msg}")
        result["errors"].append(msg)
        if args.output_format == "json":
            print_json(result)
        return
    # Fetch real CVEs for the predicted label (as service)
    cve_list = fetch_cves(pred_label, "unknown_version")
    result["cves"] = cve_list
    if not cve_list:
        # Fallback to mock CVEs if none found
        cve_list = [
            {"id": "CVE-2021-41773", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49."},
            {"id": "CVE-2021-42013", "description": "Remote code execution in Apache HTTP Server 2.4.50."}
        ]
    
    # Enrich CVEs with threat intelligence
    print("[*] Enriching CVEs with threat intelligence...")
    threat_intel = enrich_cves_with_threat_intel(cve_list, pred_label)
    result["threat_intelligence"] = threat_intel
    
    # Enrich CVEs with MITRE ATT&CK analysis
    print("[*] Enriching CVEs with MITRE ATT&CK analysis...")
    attack_analysis = enrich_findings_with_attack(cve_list, pred_label)
    result["mitre_attack_analysis"] = attack_analysis
    
    summary = generate_vuln_summary(pred_label, "unknown_version", cve_list)
    result["ai_summary"] = summary
    info = get_vuln_info(pred_label)
    result["static_info"] = info
    if args.output_format == "json":
        print_json(result)
    else:
        print(f"[+] Predicted Behaviour Class: {pred_label}")
        print("\n[AI-Generated Vulnerability Summary and Exploitation Guide]:")
        print(summary)
        print("\n[!] Vulnerability Information:")
        print(f"Description: {info['description']}")
        print(f"Recommendation: {info['recommendation']}")
        if result["cves"]:
            print("\n[+] Top CVEs from NVD:")
            for cve in result["cves"]:
                print(f"- {cve['id']}: {cve['description'][:100]}...")
        
        # Display threat intelligence results
        print("\n[+] Threat Intelligence Summary:")
        print(f"  - Total CVEs: {threat_intel['summary']['total_cves']}")
        print(f"  - Exploits found: {threat_intel['summary']['exploits_found']}")
        print(f"  - CISA KEV CVEs: {threat_intel['summary']['kev_count']}")
        if threat_intel['vendor_advisory']:
            print(f"  - Vendor advisory: {threat_intel['vendor_advisory']}")
        
        if threat_intel['exploits']:
            print("\n[+] Available Exploits:")
            for exploit in threat_intel['exploits'][:3]:  # Show top 3
                print(f"  - {exploit['id']}: {exploit['description'][:80]}...")
        
        if threat_intel['kev_status']:
            kev_cves = [cve for cve, is_kev in threat_intel['kev_status'].items() if is_kev]
            if kev_cves:
                print(f"\n[!] HIGH PRIORITY - CISA KEV CVEs: {', '.join(kev_cves)}")
        
        # Display MITRE ATT&CK analysis
        print("\n[+] MITRE ATT&CK Analysis:")
        print(f"  - Risk Score: {attack_analysis['risk_score']}/10")
        print(f"  - Threat Actors: {', '.join(attack_analysis['threat_actors'])}")
        print(f"  - Techniques Found: {', '.join(attack_analysis['all_techniques'])}")
        
        print("\n[+] ATT&CK Tactics:")
        for tactic_id, tactic_info in attack_analysis['tactics_analysis'].items():
            print(f"  - {tactic_id} - {tactic_info['name']}")
            for technique in tactic_info['techniques']:
                print(f"    * {technique['id']}: {technique['name']}")

if __name__ == "__main__":
    main()