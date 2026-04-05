#!/usr/bin/env python3
"""SentinelAI Agent Tools — Enhanced with Groq AI-powered analysis."""

import socket
import json
import requests
import os
import dns.resolver
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# ---------------------------------------------------------------------------
# Groq helper — used by tools that want AI-powered analysis
# ---------------------------------------------------------------------------

try:
    from groq import Groq as _GroqClient
    _GROQ_AVAILABLE = bool(os.getenv('GROQ_API_KEY'))
except ImportError:
    _GROQ_AVAILABLE = False


def _groq(prompt: str, max_tokens: int = 512) -> Optional[str]:
    """Call Groq LLM and return the response text, or None on failure."""
    if not _GROQ_AVAILABLE:
        return None
    try:
        client = _GroqClient(api_key=os.getenv('GROQ_API_KEY'))
        resp = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return None


# ---------------------------------------------------------------------------
# Pydantic input schemas
# ---------------------------------------------------------------------------

class ScanInput(BaseModel):
    target: str = Field(..., description="Target URL (e.g. https://example.com)")
    template: str = Field("standard", description="quick | standard | full")
    project_id: str = Field("ai_generated", description="Project identifier")


class DomainInput(BaseModel):
    domain: str = Field(..., description="Domain name (e.g. example.com)")


class ScopeInput(BaseModel):
    scope: str = Field(..., description="Scope: domain, hostname, or IP")


class ScanResultsInput(BaseModel):
    scan_results: str = Field(..., description="Raw scan results text")


# ---------------------------------------------------------------------------
# Tool: SentinelAI scan trigger
# ---------------------------------------------------------------------------

class SentinelAIScanTool(BaseTool):
    """Trigger a SentinelAI security scan via the backend API."""

    name: str = "sentinelai_scan"
    description: str = "Start a SentinelAI scan for a target URL using quick/standard/full templates."
    args_schema: type[BaseModel] = ScanInput

    def _run(self, target: str, template: str = "standard", project_id: str = "ai_generated") -> str:
        try:
            payload = {
                "projectId": project_id,
                "target": target,
                "template": template,
                "aiInitiated": True,
                "modules": self._modules(template),
            }
            r = requests.post(
                "http://localhost:5000/api/scan/start",
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=30,
            )
            if r.status_code == 201:
                s = r.json().get('scan', {})
                return f"Scan started for {target}\nID: {s.get('id')}\nStatus: {s.get('status')}"
            return f"Scan failed: HTTP {r.status_code} — {r.text}"
        except requests.exceptions.ConnectionError:
            return "Cannot reach SentinelAI backend at localhost:5000. Ensure the server is running."
        except Exception as e:
            return f"Scan execution error: {e}"

    def _modules(self, template: str) -> dict:
        T = {
            "quick":    dict(headers=True, ssl=True, paths=False, dns=False, cors=False, tech=False, subdomains=False, info=False, external=False, nuclei=False, kali_advanced=False),
            "standard": dict(headers=True, ssl=True, paths=True,  dns=True,  cors=True,  tech=True,  subdomains=False, info=False, external=False, nuclei=False, kali_advanced=False),
            "full":     dict(headers=True, ssl=True, paths=True,  dns=True,  cors=True,  tech=True,  subdomains=True,  info=True,  external=True,  nuclei=True,  kali_advanced=True),
        }
        return T.get(template, T["standard"])


# ---------------------------------------------------------------------------
# Tool: Subdomain discovery (DNS brute-force + Certificate Transparency)
# ---------------------------------------------------------------------------

class SubdomainDiscoveryTool(BaseTool):
    """Discover subdomains via DNS brute-force and certificate transparency logs."""

    name: str = "subdomain_discovery"
    description: str = "Discover active subdomains using DNS and crt.sh CT logs."
    args_schema: type[BaseModel] = DomainInput

    _WORDLIST = [
        "www", "mail", "ftp", "test", "dev", "staging", "api", "admin", "app",
        "blog", "shop", "cdn", "beta", "alpha", "vpn", "portal", "support",
        "docs", "wiki", "forum", "store", "mobile", "secure", "login", "auth",
        "api-v2", "api-v1", "rest", "graphql", "ws", "static", "assets",
        "images", "media", "download", "upload", "git", "gitlab", "jenkins",
        "ci", "jira", "confluence", "status", "monitor", "dashboard", "internal",
        "intranet", "backup", "old", "demo", "sandbox", "uat", "qa", "preprod",
        "db", "database", "redis", "elastic", "kibana", "grafana", "smtp", "pop",
        "imap", "webmail", "cpanel", "whm", "remote", "cloud",
    ]

    def _run(self, domain: str) -> str:
        found: set[str] = set()

        # 1. DNS brute-force
        for sub in self._WORDLIST:
            host = f"{sub}.{domain}"
            try:
                socket.gethostbyname(host)
                found.add(host)
            except socket.gaierror:
                pass

        # 2. Certificate Transparency (crt.sh)
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=12,
                headers={"User-Agent": "SentinelAI/1.0"},
            )
            if resp.status_code == 200:
                for entry in resp.json()[:200]:
                    for name in entry.get('name_value', '').split('\n'):
                        name = name.strip().lstrip('*.')
                        if name.endswith(f'.{domain}') or name == domain:
                            try:
                                socket.gethostbyname(name)
                                found.add(name)
                            except socket.gaierror:
                                pass
        except Exception:
            pass

        unique = sorted(found)
        if not unique:
            return f"No subdomains discovered for {domain}"

        sensitive_prefixes = {'admin', 'dev', 'staging', 'test', 'internal', 'intranet',
                              'backup', 'db', 'database', 'jenkins', 'gitlab', 'ci', 'vpn'}
        sensitive = [h for h in unique if h.split('.')[0] in sensitive_prefixes]

        out = [f"Discovered {len(unique)} subdomains for {domain}:"]
        for h in unique:
            tag = " ⚠️ SENSITIVE" if h in sensitive else ""
            out.append(f"  • https://{h}{tag}")
        if sensitive:
            out.append(f"\n[!] {len(sensitive)} sensitive subdomain(s) require priority review")
        return '\n'.join(out)


# ---------------------------------------------------------------------------
# Tool: DNS reconnaissance
# ---------------------------------------------------------------------------

class DnsTool(BaseTool):
    """Comprehensive DNS reconnaissance and email security analysis."""

    name: str = "dns_recon"
    description: str = "Collect DNS records (A/MX/NS/TXT/SOA) and check SPF/DKIM/DMARC."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> str:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        info: dict[str, list[str]] = {}
        for rtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'):
            try:
                info[rtype] = [str(a) for a in resolver.resolve(domain, rtype)]
            except Exception:
                info[rtype] = []

        lines = [f"DNS Reconnaissance — {domain}", ""]
        for rtype, records in info.items():
            if records:
                lines.append(f"{rtype} Records:")
                for r in records:
                    lines.append(f"  • {r}")
                lines.append("")

        # --- Email security ---
        lines.append("Email Security:")
        spf = next((r for r in info.get('TXT', []) if 'v=spf1' in r), None)
        if spf:
            lines.append(f"  SPF ✓  {spf}")
            if '+all' in spf:
                lines.append("    ⚠️  SPF uses +all — allows ALL senders (critical misconfiguration)")
            elif '~all' in spf:
                lines.append("    ℹ️  SPF uses ~all (softfail — consider upgrading to -all)")
        else:
            lines.append("  SPF ✗  Missing — email spoofing is possible")

        try:
            dmarc_ans = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc = ' '.join(str(r) for r in dmarc_ans)
            lines.append(f"  DMARC ✓  {dmarc}")
            if 'p=none' in dmarc:
                lines.append("    ⚠️  DMARC policy=none — monitoring only, no enforcement")
        except Exception:
            lines.append("  DMARC ✗  Missing — no email authentication enforcement")

        # Check DKIM common selectors
        dkim_selectors = ['default', 'google', 'mail', 'email', 'selector1', 'selector2', 'k1']
        for sel in dkim_selectors:
            try:
                resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
                lines.append(f"  DKIM ✓  Selector '{sel}' found")
                break
            except Exception:
                pass

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Tool: AI-powered threat intelligence
# ---------------------------------------------------------------------------

class ThreatIntelTool(BaseTool):
    """Domain threat intelligence: DNS reputation checks + Groq AI analysis."""

    name: str = "threat_intel"
    description: str = "Analyze a domain for known threats using DNS blocklists and AI."
    args_schema: type[BaseModel] = DomainInput

    _HIGH_RISK_TLDS = {'.tk', '.ml', '.ga', '.cf', '.bit', '.xyz', '.top', '.pw', '.cc', '.su'}
    _SUSPICIOUS_KW  = ['login', 'secure', 'account', 'verify', 'update', 'confirm',
                       'bank', 'paypal', 'apple', 'amazon', 'microsoft', 'google',
                       'facebook', 'support', 'helpdesk', 'password', 'wallet']

    def _run(self, domain: str) -> str:
        raw = self._gather(domain)
        if _GROQ_AVAILABLE:
            return self._ai_enrich(domain, raw)
        return raw

    def _gather(self, domain: str) -> str:
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        lines = [f"Threat Intel — {domain}", f"Timestamp: {now}", ""]

        # TLD risk
        tld = '.' + domain.rsplit('.', 1)[-1].lower()
        lines.append(f"TLD: {tld}  {'[HIGH RISK]' if tld in self._HIGH_RISK_TLDS else '[OK]'}")

        # Length / structure
        if len(domain) > 50:
            lines.append(f"Domain length {len(domain)}: [SUSPICIOUS — unusually long]")
        digits = sum(1 for c in domain if c.isdigit())
        if digits > 4:
            lines.append(f"Digits in domain: {digits}  [SUSPICIOUS]")

        # Suspicious keywords
        kw_hits = [k for k in self._SUSPICIOUS_KW if k in domain.lower()]
        if kw_hits:
            lines.append(f"Suspicious keywords: {', '.join(kw_hits)}")

        # DNS reputation (DNSBL checks)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 8

        checks = [
            (f"{domain}.dbl.spamhaus.org",    "Spamhaus DBL (spam/phishing domains)"),
            (f"{domain}.multi.surbl.org",     "SURBL (known malicious domains)"),
            (f"{domain}.uribl.com",           "URIBL (URI-based spam)"),
        ]
        lines.append("\nDNS Reputation Checks:")
        for query, label in checks:
            try:
                resolver.resolve(query, 'A')
                lines.append(f"  ⚠️  LISTED in {label}")
            except dns.resolver.NXDOMAIN:
                lines.append(f"  ✓  Not listed in {label}")
            except Exception:
                lines.append(f"  –  {label}: check unavailable")

        # Certificate transparency
        try:
            ct = requests.get(
                f"https://crt.sh/?q={domain}&output=json&limit=3",
                timeout=8,
                headers={"User-Agent": "SentinelAI/1.0"},
            )
            if ct.status_code == 200 and ct.json():
                certs = ct.json()
                lines.append(f"\nCertificate Transparency: {len(certs)}+ certificate(s) found")
                latest = certs[0]
                lines.append(f"  Latest issued: {latest.get('not_before', 'unknown')}")
                lines.append(f"  Issuer: {latest.get('issuer_name', 'unknown')}")
        except Exception:
            pass

        return '\n'.join(lines)

    def _ai_enrich(self, domain: str, raw: str) -> str:
        prompt = f"""You are a cybersecurity threat intelligence analyst.

Analyze the following domain intelligence data and provide a concise threat assessment:

Domain: {domain}
Intelligence Data:
{raw}

Provide:
1. Overall threat level: Low / Medium / High / Critical
2. Key risk indicators (bullet points)
3. Most likely threat category (phishing / spam / malware / legitimate / suspicious)
4. Recommended immediate actions
5. Confidence level (%)

Be specific and actionable. Maximum 300 words."""

        ai = _groq(prompt, max_tokens=400)
        if ai:
            return f"{raw}\n\n{'='*40}\nAI Threat Assessment (Groq)\n{'='*40}\n{ai}"
        return raw


# ---------------------------------------------------------------------------
# Tool: AI-powered vulnerability analysis
# ---------------------------------------------------------------------------

class VulnerabilityAnalysisTool(BaseTool):
    """Analyze scan results with Groq AI for intelligent vulnerability prioritization."""

    name: str = "vulnerability_analysis"
    description: str = "AI-powered analysis and prioritization of vulnerability scan results."
    args_schema: type[BaseModel] = ScanResultsInput

    def _run(self, scan_results: str) -> str:
        if _GROQ_AVAILABLE:
            return self._ai_analyze(scan_results)
        return self._basic_analyze(scan_results)

    def _ai_analyze(self, scan_results: str) -> str:
        # Truncate to stay within context limits
        truncated = scan_results[:3500] if len(scan_results) > 3500 else scan_results

        prompt = f"""You are a senior penetration tester and vulnerability analyst.

Analyze these security scan results and provide a structured assessment:

{truncated}

Structure your response as:

## CRITICAL (Immediate action required)
- List each critical finding with CVE if known

## HIGH (Fix within 24-48 hours)
- List each high finding

## MEDIUM/LOW (Fix within 30 days)
- Summary

## Attack Chain Analysis
- Can any findings be chained for greater impact? Explain.

## Top 5 Remediation Priorities
1.
2.
3.
4.
5.

## Risk Score: X/10
Justification: (one sentence)

Be specific, technical, and actionable."""

        result = _groq(prompt, max_tokens=700)
        if result:
            return result
        return self._basic_analyze(scan_results)

    def _basic_analyze(self, scan_results: str) -> str:
        lines = ["Vulnerability Analysis Report", "=" * 40]
        lower = scan_results.lower()

        tiers = {
            'CRITICAL': ['sql injection', 'remote code execution', 'rce', 'command injection',
                         'heartbleed', 'shellshock', 'deserialization', 'xxe', 'critical'],
            'HIGH':     ['xss', 'cross-site scripting', 'authentication bypass', 'ssrf',
                         'idor', 'path traversal', 'lfi', 'rfi', 'open redirect', 'high'],
            'MEDIUM':   ['csrf', 'cors misconfiguration', 'information disclosure',
                         'default credentials', 'medium'],
            'LOW':      ['missing header', 'insecure cookie', 'tls 1.0', 'weak cipher', 'low'],
        }

        for tier, keywords in tiers.items():
            if any(k in lower for k in keywords):
                lines.append(f"\n[{tier}] Issues detected — review scan output for details")

        lines.extend([
            "\nGeneral Remediation Priorities:",
            "• Critical: Patch immediately (same day)",
            "• High: Fix within 24-48 hours",
            "• Medium: Schedule within 1-2 weeks",
            "• Low: Address in next maintenance window",
            "• Enable WAF for layered protection",
        ])
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Tool: Asset discovery with service fingerprinting
# ---------------------------------------------------------------------------

class AssetDiscoveryTool(BaseTool):
    """Discover live services, open ports, and exposed infrastructure."""

    name: str = "asset_discovery"
    description: str = "Discover reachable services and asset context for a scope."
    args_schema: type[BaseModel] = ScopeInput

    # port → (protocol, service label, risk_note)
    _PORTS = {
        80:    ('http',  'HTTP Web Server',         ''),
        443:   ('https', 'HTTPS Web Server',        ''),
        8080:  ('http',  'HTTP Alt / Dev Server',   ''),
        8443:  ('https', 'HTTPS Alt',               ''),
        3000:  ('http',  'Node.js / Dev',           'May expose dev endpoints'),
        5000:  ('http',  'Flask / Dev',             ''),
        8000:  ('http',  'Django / Dev',            ''),
        4200:  ('http',  'Angular Dev',             ''),
        3001:  ('http',  'React Dev',               ''),
        8888:  ('http',  'Jupyter Notebook',        '⚠️ Often unauthenticated!'),
        9200:  ('http',  'Elasticsearch',           '⚠️ Often unauthenticated!'),
        5601:  ('http',  'Kibana',                  '⚠️ May expose sensitive logs'),
        6379:  ('tcp',   'Redis',                   '⚠️ No auth by default!'),
        27017: ('tcp',   'MongoDB',                 '⚠️ No auth by default!'),
        3306:  ('tcp',   'MySQL',                   '⚠️ Should not be public'),
        5432:  ('tcp',   'PostgreSQL',              '⚠️ Should not be public'),
        1433:  ('tcp',   'MSSQL',                   '⚠️ Should not be public'),
        22:    ('ssh',   'SSH',                     ''),
        21:    ('ftp',   'FTP',                     '⚠️ Cleartext protocol'),
        23:    ('telnet','Telnet',                  '⚠️ Cleartext — critical risk'),
        25:    ('smtp',  'SMTP',                    ''),
        445:   ('smb',   'SMB',                     '⚠️ Should not be internet-facing'),
        3389:  ('rdp',   'RDP',                     '⚠️ Brute-force target'),
    }

    def _run(self, scope: str) -> str:
        hostname = scope.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
        lines = [f"Asset Discovery — {hostname}", ""]

        live = []
        for port, (proto, label, risk) in self._PORTS.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((hostname, port)) == 0:
                    if port == 443 or (port == 80):
                        url = f"{proto}://{hostname}"
                    else:
                        url = f"{proto}://{hostname}:{port}"
                    live.append({'url': url, 'port': port, 'label': label, 'risk': risk})
                s.close()
            except Exception:
                pass

        if live:
            lines.append(f"Live Services ({len(live)} found):")
            for svc in live:
                lines.append(f"  [{svc['port']:5d}] {svc['url']:<45} {svc['label']}")
                if svc['risk']:
                    lines.append(f"           {svc['risk']}")
        else:
            lines.append("No common services detected. Run nmap for full port scan.")

        lines.extend([
            "",
            "Recommended Follow-up:",
            "  • nmap full scan: nmap -sV -sC -p- --open " + hostname,
            "  • Check all services for default credentials",
            "  • Verify databases are not publicly accessible",
            "  • Review firewall rules for unnecessary exposure",
        ])

        # AI enrichment when services found
        if _GROQ_AVAILABLE and live:
            summary = ', '.join(f"{s['label']}:{s['port']}" for s in live)
            ai = _groq(
                f"Security assessment: host '{hostname}' exposes: {summary}. "
                "List the top 3 security risks in order of severity with one-line remediation each.",
                max_tokens=250,
            )
            if ai:
                lines.extend(["", "--- AI Risk Summary ---", ai])

        return '\n'.join(lines)
