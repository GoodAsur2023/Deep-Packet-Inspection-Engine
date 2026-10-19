#!/usr/bin/env python3
"""
AegisFlow Security Control Plane - CVE Correlator & Automated Remediation Advisor
Author: Shrest Kumar

Consumes telemetry emitted by the C++ AegisFlow DPI engine (alerts.jsonl),
correlates exposed services and weak cryptographic postures with known CVEs,
and generates automated remediation playbooks (hardening configs, firewall isolation, upgrade commands).
"""

import json
import os
import sys
import argparse
from typing import Dict, List, Any

# Local CVE knowledge base mapping banners and posture anomalies to vulnerability feeds
CVE_KNOWLEDGE_BASE = {
    "CVE-2021-41773": {
        "title": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "affected": "Apache/2.4.49",
        "remediation_config": """# /etc/apache2/conf-available/security-hardening.conf
<Directory />
    Require all denied
</Directory>
ServerSignature Off
ServerTokens Prod
""",
        "remediation_command": "sudo apt-get update && sudo apt-get --only-upgrade install apache2 -y"
    },
    "CVE-2016-10009": {
        "title": "OpenSSH Privilege Escalation via Forwarded ssh-agent",
        "cvss": 7.8,
        "severity": "HIGH",
        "affected": "OpenSSH < 7.4",
        "remediation_config": """# /etc/ssh/sshd_config.d/hardening.conf
Protocol 2
PermitRootLogin no
MaxAuthTries 3
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
""",
        "remediation_command": "sudo apt-get update && sudo apt-get --only-upgrade install openssh-server -y"
    },
    "DEPRECATED_TLS": {
        "title": "Deprecated TLS 1.0/1.1 Protocol Negotiation (RFC 8996)",
        "cvss": 7.4,
        "severity": "HIGH",
        "affected": "TLS 1.0, TLS 1.1, SSL 3.0",
        "remediation_config": """# Modern SSL configuration (nginx.conf / ssl.conf)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
""",
        "remediation_command": "# Enforce TLS 1.2+ minimum on web servers and load balancers"
    },
    "WEAK_CIPHERS": {
        "title": "Insecure Legacy Cipher Suites Offered (SWEET32 / RC4 / Non-PFS)",
        "cvss": 5.9,
        "severity": "MEDIUM",
        "affected": "3DES (DES-CBC3-SHA), RC4, EXPORT, Static RSA",
        "remediation_config": """# Disable weak 64-bit block and stream ciphers
ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!RC4:!DES:!DSS:!SEED:!IDEA;
""",
        "remediation_command": "openssl ciphers -v 'HIGH:!aNULL:!MD5:!3DES:!RC4'"
    }
}


class ControlPlane:
    def __init__(self, alerts_file: str):
        self.alerts_file = alerts_file
        self.alerts: List[Dict[str, Any]] = []

    def load_alerts(self) -> bool:
        if not os.path.exists(self.alerts_file):
            print(f"[!] Alerts file not found: {self.alerts_file}")
            return False

        with open(self.alerts_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self.alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return True

    def analyze(self) -> Dict[str, Any]:
        report = {
            "total_alerts": len(self.alerts),
            "hosts_at_risk": set(),
            "critical_cves": [],
            "posture_anomalies": [],
            "remediations": []
        }

        seen_remediations = set()

        for alert in self.alerts:
            src_ip = alert.get("src_ip", "unknown")
            alert_type = alert.get("alert_type", "")
            desc = alert.get("description", "")
            banner = alert.get("service_banner", "")

            # Check known CVE triggers
            matched_key = None
            if "CVE-2021-41773" in desc or "Apache/2.4.49" in banner:
                matched_key = "CVE-2021-41773"
            elif "CVE-2016-10009" in desc or "OpenSSH_7.4" in banner:
                matched_key = "CVE-2016-10009"
            elif alert_type == "DEPRECATED_TLS":
                matched_key = "DEPRECATED_TLS"
            elif alert_type == "WEAK_CIPHERS":
                matched_key = "WEAK_CIPHERS"

            if matched_key and matched_key not in seen_remediations:
                seen_remediations.add(matched_key)
                kb_entry = CVE_KNOWLEDGE_BASE[matched_key]
                report["hosts_at_risk"].add(src_ip)
                
                remediation_item = {
                    "rule_id": matched_key,
                    "title": kb_entry["title"],
                    "severity": kb_entry["severity"],
                    "cvss": kb_entry["cvss"],
                    "host": src_ip,
                    "evidence": banner or desc,
                    "config_patch": kb_entry["remediation_config"],
                    "command": kb_entry["remediation_command"],
                    "firewall_rule": f"sudo iptables -A INPUT -s {src_ip} -j DROP" if kb_entry["severity"] == "CRITICAL" else ""
                }
                report["remediations"].append(remediation_item)

        report["hosts_at_risk"] = list(report["hosts_at_risk"])
        return report

    def print_summary(self, analysis: Dict[str, Any]):
        print("\n" + "=" * 64)
        print("    AegisFlow Control Plane - Security & Remediation Report")
        print("=" * 64)
        print(f"Total Telemetry Alerts Processed: {analysis['total_alerts']}")
        print(f"Identified Hosts with Posture Risks: {len(analysis['hosts_at_risk'])}")
        print(f"Automated Remediation Playbooks:    {len(analysis['remediations'])}")
        print("-" * 64)

        for idx, rem in enumerate(analysis["remediations"], 1):
            sev_badge = f"[{rem['severity']}]"
            print(f"\n{idx}. {sev_badge} {rem['title']} (CVSS {rem['cvss']})")
            print(f"   Target Host: {rem['host']}")
            print(f"   Evidence:    {rem['evidence']}")
            print("   --- Automated Hardening Patch ---")
            for line in rem['config_patch'].strip().split('\n'):
                print(f"   | {line}")
            print(f"   Remediation Command: {rem['command']}")
            if rem['firewall_rule']:
                print(f"   Containment Firewall Rule: {rem['firewall_rule']}")

        print("\n" + "=" * 64 + "\n")

    def export_playbook(self, analysis: Dict[str, Any], output_md: str):
        with open(output_md, 'w', encoding='utf-8') as f:
            f.write("# AegisFlow Automated Remediation Playbook\n\n")
            f.write(f"Generated from `{self.alerts_file}` with {analysis['total_alerts']} telemetry alerts.\n\n")
            f.write("## Executive Summary\n\n")
            f.write(f"- **Vulnerable / At-Risk Hosts**: {', '.join(analysis['hosts_at_risk']) or 'None'}\n")
            f.write(f"- **Identified Vulnerability Playbooks**: {len(analysis['remediations'])}\n\n")
            f.write("## Remediation Items\n\n")

            for rem in analysis["remediations"]:
                f.write(f"### [{rem['severity']}] {rem['title']} (CVSS {rem['cvss']})\n\n")
                f.write(f"- **Affected Host**: `{rem['host']}`\n")
                f.write(f"- **Observed Telemetry**: `{rem['evidence']}`\n\n")
                f.write("#### Recommended Configuration Hardening\n```apache\n")
                f.write(rem['config_patch'])
                f.write("```\n\n")
                f.write("#### Package Upgrade Command\n```bash\n")
                f.write(rem['command'] + "\n```\n\n")
                if rem['firewall_rule']:
                    f.write("#### Immediate Network Isolation (Optional)\n```bash\n")
                    f.write(rem['firewall_rule'] + "\n```\n\n")
                f.write("---\n\n")
        print(f"[+] Remediation playbook saved to: {output_md}")


def main():
    parser = argparse.ArgumentParser(description="AegisFlow Control Plane - CVE Correlator & Remediation Advisor")
    parser.add_argument("--alerts", default="alerts.jsonl", help="Path to alerts.jsonl from DPI engine")
    parser.add_argument("--export-md", default="remediation_playbook.md", help="Path to export Markdown remediation playbook")
    args = parser.parse_args()

    cp = ControlPlane(args.alerts)
    if cp.load_alerts():
        analysis = cp.analyze()
        cp.print_summary(analysis)
        cp.export_playbook(analysis, args.export_md)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
