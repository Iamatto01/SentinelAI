#!/usr/bin/env python3
"""SentinelAI Agent Tools.

CrewAI requires tools to be instances of ``BaseTool``. These wrappers expose
the existing helper logic through CrewAI-compatible tool classes.
"""

import subprocess
import json
import requests
import os
import dns.resolver
import socket
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

class ScanInput(BaseModel):
    target: str = Field(..., description="Target URL (for example: https://example.com)")
    template: str = Field("standard", description="Scan template: quick, standard, or full")
    project_id: str = Field("ai_generated", description="Project identifier for scan association")


class DomainInput(BaseModel):
    domain: str = Field(..., description="Domain name to analyze (for example: example.com)")


class ScopeInput(BaseModel):
    scope: str = Field(..., description="Scope value such as domain, hostname, or IP range")


class ScanResultsInput(BaseModel):
    scan_results: str = Field(..., description="Raw or summarized scan results text")


class SentinelAIScanTool(BaseTool):
    """Execute SentinelAI security scans using the existing scanner system."""

    name: str = "sentinelai_scan"
    description: str = "Start a SentinelAI scan for a target URL using quick/standard/full templates."
    args_schema: type[BaseModel] = ScanInput

    def _run(self, target: str, template: str = "standard", project_id: str = "ai_generated") -> str:
        """Execute a scan using SentinelAI backend API"""
        try:
            # Prepare scan request
            scan_data = {
                "projectId": project_id,
                "target": target,
                "template": template,
                "aiInitiated": True,
                "modules": self._get_template_modules(template)
            }

            # Send scan request to SentinelAI backend
            response = requests.post(
                "http://localhost:5000/api/scan/start",
                headers={"Content-Type": "application/json"},
                json=scan_data,
                timeout=30
            )

            if response.status_code == 201:
                scan_info = response.json()
                scan_obj = scan_info.get('scan', {}) if isinstance(scan_info, dict) else {}
                scan_id = scan_obj.get('id')
                status = scan_obj.get('status')
                return f"Scan initiated successfully for {target}\nScan ID: {scan_id}\nTemplate: {template}\nStatus: {status}"
            else:
                return f"Scan failed: HTTP {response.status_code} - {response.text}"

        except requests.exceptions.ConnectionError:
            return "Cannot connect to SentinelAI backend at localhost:5000. Ensure the server is running."
        except Exception as e:
            return f"Scan execution failed: {str(e)}"

    def _get_template_modules(self, template: str) -> dict:
        """Get module configuration for scan templates"""
        templates = {
            "quick": {
                "headers": True, "ssl": True,
                "paths": False, "dns": False, "cors": False, "tech": False,
                "subdomains": False, "info": False, "external": False,
                "nuclei": False, "kali_advanced": False,
            },
            "standard": {
                "headers": True, "ssl": True, "paths": True, "dns": True, "cors": True, "tech": True,
                "subdomains": False, "info": False, "external": False,
                "nuclei": False, "kali_advanced": False,
            },
            "full": {
                "headers": True, "ssl": True, "paths": True, "dns": True, "cors": True, "tech": True,
                "subdomains": True, "info": True, "external": True,
                "nuclei": True, "kali_advanced": True,
            }
        }
        return templates.get(template, templates["standard"])


class SubdomainDiscoveryTool(BaseTool):
    """Discover subdomains for a given domain using DNS techniques."""

    name: str = "subdomain_discovery"
    description: str = "Discover common active subdomains for a domain."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> str:
        """Discover subdomains for the given domain"""
        try:
            subdomains = []
            common_subdomains = [
                "www", "mail", "ftp", "test", "dev", "staging", "api", "admin", "app",
                "blog", "shop", "cdn", "beta", "alpha", "vpn", "portal", "support",
                "docs", "wiki", "forum", "store", "mobile", "secure", "login"
            ]

            # Test common subdomains
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    socket.gethostbyname(full_domain)
                    subdomains.append(full_domain)
                except socket.gaierror:
                    continue

            # Try DNS enumeration
            try:
                resolver = dns.resolver.Resolver()
                # Try some additional DNS records
                for record_type in ['A', 'CNAME']:
                    try:
                        answers = resolver.resolve(domain, record_type)
                        for answer in answers:
                            if hasattr(answer, 'target'):
                                target_str = str(answer.target).rstrip('.')
                                if target_str.endswith(domain):
                                    subdomains.append(target_str)
                    except:
                        continue
            except:
                pass

            # Remove duplicates and sort
            unique_subdomains = list(set(subdomains))
            unique_subdomains.sort()

            if unique_subdomains:
                result = f"Discovered {len(unique_subdomains)} subdomains for {domain}:\n"
                for subdomain in unique_subdomains:
                    result += f"  • https://{subdomain}\n"
                return result
            else:
                return f"No subdomains discovered for {domain} using basic techniques"

        except Exception as e:
            return f"Subdomain discovery failed: {str(e)}"


class DnsTool(BaseTool):
    """Perform DNS reconnaissance to gather information about domain infrastructure."""

    name: str = "dns_recon"
    description: str = "Collect DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for a domain."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> str:
        """Perform DNS reconnaissance"""
        try:
            resolver = dns.resolver.Resolver()
            dns_info = {}

            # Common DNS record types to query
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(answer) for answer in answers]
                except dns.resolver.NoAnswer:
                    dns_info[record_type] = []
                except Exception as e:
                    dns_info[record_type] = [f"Error: {str(e)}"]

            # Format results
            result = f"DNS Reconnaissance for {domain}:\n"
            for record_type, records in dns_info.items():
                if records:
                    result += f"\n{record_type} Records:\n"
                    for record in records:
                        result += f"  • {record}\n"

            # Look for interesting TXT records
            txt_records = dns_info.get('TXT', [])
            interesting_txt = []
            for txt in txt_records:
                if any(keyword in txt.lower() for keyword in ['spf', 'dmarc', 'dkim', 'google-site-verification']):
                    interesting_txt.append(txt)

            if interesting_txt:
                result += "\nEmail Security Records Found:\n"
                for txt in interesting_txt:
                    result += f"  • {txt}\n"

            return result

        except Exception as e:
            return f"DNS reconnaissance failed: {str(e)}"


class ThreatIntelTool(BaseTool):
    """Analyze domain for known threats, reputation, and security indicators."""

    name: str = "threat_intel"
    description: str = "Perform lightweight domain threat-intelligence heuristics and risk hints."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> str:
        """Analyze domain threat intelligence"""
        try:
            intel_report = []

            # Basic domain analysis
            intel_report.append(f"Threat Intelligence Report for {domain}")

            # Check domain age and basic info (simulated)
            intel_report.append("Domain Analysis:")
            intel_report.append(f"  • Domain: {domain}")
            intel_report.append(f"  • Analysis Date: {os.popen('date').read().strip()}")

            # Check for common threat indicators in domain name
            threat_keywords = ['phishing', 'malware', 'spam', 'fraud', 'scam', 'fake']
            found_keywords = [kw for kw in threat_keywords if kw in domain.lower()]

            if found_keywords:
                intel_report.append(f"Suspicious Keywords Found: {', '.join(found_keywords)}")
            else:
                intel_report.append("No obvious threat keywords detected in domain")

            # Analyze TLD risk
            high_risk_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
            domain_tld = '.' + domain.split('.')[-1]
            if domain_tld in high_risk_tlds:
                intel_report.append(f"High-risk TLD detected: {domain_tld}")
            else:
                intel_report.append(f"TLD appears legitimate: {domain_tld}")

            # Check domain length and structure
            if len(domain) > 50:
                intel_report.append("Unusually long domain name (possible phishing indicator)")
            elif len(domain) < 5:
                intel_report.append("Very short domain name (investigate further)")

            # Domain character analysis
            if any(char.isdigit() for char in domain):
                digit_count = sum(1 for char in domain if char.isdigit())
                if digit_count > 3:
                    intel_report.append(f"High number of digits in domain: {digit_count}")

            intel_report.append("\nRecommendation: Proceed with security scanning to identify vulnerabilities")

            return '\n'.join(intel_report)

        except Exception as e:
            return f"Threat intelligence analysis failed: {str(e)}"


class VulnerabilityAnalysisTool(BaseTool):
    """Analyze scan results to prioritize vulnerabilities and suggest remediation."""

    name: str = "vulnerability_analysis"
    description: str = "Summarize and prioritize vulnerabilities from scan results text."
    args_schema: type[BaseModel] = ScanResultsInput

    def _run(self, scan_results: str) -> str:
        """Analyze vulnerability scan results"""
        try:
            analysis = []
            analysis.append("Vulnerability Analysis Report")

            # Parse scan results (simplified)
            if "Critical" in scan_results:
                analysis.append("CRITICAL VULNERABILITIES DETECTED!")
                analysis.append("Immediate action required to address critical security issues.")

            if "High" in scan_results:
                analysis.append("High severity vulnerabilities found.")
                analysis.append("Schedule remediation within 24-48 hours.")

            if "Medium" in scan_results:
                analysis.append("Medium severity issues identified.")
                analysis.append("Plan remediation within 1-2 weeks.")

            if "Low" in scan_results:
                analysis.append("Low severity findings noted.")
                analysis.append("Address during regular maintenance windows.")

            # Provide general security recommendations
            analysis.append("\nSecurity Recommendations:")
            analysis.append("• Ensure all software is up to date")
            analysis.append("• Implement proper access controls")
            analysis.append("• Regular security monitoring")
            analysis.append("• Employee security training")

            return '\n'.join(analysis)

        except Exception as e:
            return f"Vulnerability analysis failed: {str(e)}"


class AssetDiscoveryTool(BaseTool):
    """Discover and enumerate assets for a given scope or organization."""

    name: str = "asset_discovery"
    description: str = "Discover reachable services and basic asset context for a scope."
    args_schema: type[BaseModel] = ScopeInput

    def _run(self, scope: str) -> str:
        """Discover assets within the given scope"""
        try:
            discoveries = []
            discoveries.append(f"Asset Discovery Report for: {scope}")

            # Parse scope (could be domain, IP range, etc.)
            if '.' in scope and not scope.replace('.', '').isdigit():
                # Looks like a domain
                discoveries.append(f"\nDomain-based discovery for: {scope}")

                # Common service ports to check
                common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
                live_services = []

                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3)
                        result = sock.connect_ex((scope, port))
                        sock.close()

                        if result == 0:
                            protocol = "https" if port in [443, 8443] else "http"
                            service_url = f"{protocol}://{scope}:{port}"
                            live_services.append(service_url)
                    except:
                        continue

                if live_services:
                    discoveries.append("\nLive Services Detected:")
                    for service in live_services:
                        discoveries.append(f"  • {service}")
                else:
                    discoveries.append("\nNo common web services detected")

            # Asset categorization
            discoveries.append("\nAsset Classification:")
            discoveries.append(f"  • Primary Target: {scope}")
            discoveries.append(f"  • Asset Type: Web Application/Service")
            discoveries.append(f"  • Discovery Method: Port Scanning")

            # Recommended next steps
            discoveries.append("\nRecommended Actions:")
            discoveries.append(f"  • Run full security scan on discovered assets")
            discoveries.append(f"  • Perform subdomain enumeration")
            discoveries.append(f"  • Check for exposed directories/files")
            discoveries.append(f"  • Analyze SSL/TLS configuration")

            return '\n'.join(discoveries)

        except Exception as e:
            return f"Asset discovery failed: {str(e)}"