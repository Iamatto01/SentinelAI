#!/usr/bin/env python3
"""
SentinelAI Agent Crew
AI agents for autonomous security scanning using CrewAI + Groq
"""

import os
import json
from crewai import Agent, Task, Crew, Process
from dotenv import load_dotenv
from tools import (
    SentinelAIScanTool, SubdomainDiscoveryTool, DnsTool,
    ThreatIntelTool, VulnerabilityAnalysisTool, AssetDiscoveryTool
)

# Load environment variables
load_dotenv()

# CrewAI accepts provider/model strings for LLM selection.
# GROQ_API_KEY is read from the environment by the provider integration.
groq_llm = "groq/llama-3.1-8b-instant"

# Initialize tools
sentinel_scanner = SentinelAIScanTool()
subdomain_discovery = SubdomainDiscoveryTool()
dns_recon = DnsTool()
threat_intel = ThreatIntelTool()
vuln_analysis = VulnerabilityAnalysisTool()
asset_discovery = AssetDiscoveryTool()

# ═══════════════════════════════════════════════════════════════════════════════
# Agent Definitions
# ═══════════════════════════════════════════════════════════════════════════════

recon_agent = Agent(
    role="Security Reconnaissance Specialist",
    goal="Discover and enumerate target assets, subdomains, and attack surfaces for comprehensive security assessment",
    backstory="""\
You are an expert in cybersecurity reconnaissance with deep knowledge of:
• Asset discovery techniques and methodologies
• Subdomain enumeration and DNS analysis
• Threat intelligence gathering and analysis
• OSINT (Open Source Intelligence) techniques
• Infrastructure mapping and service discovery

Your mission is to thoroughly map the attack surface of target organizations
while staying within legal and ethical boundaries. You provide detailed
reconnaissance reports that enable effective security testing.
    """,
    verbose=True,
    allow_delegation=False,
    llm=groq_llm,
    tools=[subdomain_discovery, dns_recon, threat_intel, asset_discovery],
    max_iter=3
)

scanner_agent = Agent(
    role="Security Scanner Coordinator",
    goal="Execute comprehensive security scans and coordinate testing across discovered assets using SentinelAI platform",
    backstory="""\
You are an expert security scanner operator with extensive knowledge of:
• Vulnerability scanning methodologies and best practices
• Security testing frameworks and tools (Nuclei, Nmap, etc.)
• Scan optimization and resource management
• Result interpretation and false positive filtering
• Risk-based scanning prioritization

You coordinate with the SentinelAI platform to execute sophisticated security
scans, optimize scan parameters based on target characteristics, and ensure
comprehensive coverage of the attack surface.
    """,
    verbose=True,
    allow_delegation=True,
    llm=groq_llm,
    tools=[sentinel_scanner, asset_discovery],
    max_iter=5
)

analyst_agent = Agent(
    role="Vulnerability Analysis Expert",
    goal="Analyze scan results to identify, prioritize, and validate security vulnerabilities with actionable remediation guidance",
    backstory="""\
You are a senior vulnerability analyst with expertise in:
• CVSS scoring and risk assessment methodologies
• Vulnerability classification and impact analysis
• False positive identification and filtering
• Exploit development and attack chain analysis
• Business risk assessment and prioritization

Your role is to transform raw scan results into actionable intelligence,
providing clear risk assessments and specific remediation guidance that
security teams can immediately implement.
    """,
    verbose=True,
    allow_delegation=False,
    llm=groq_llm,
    tools=[vuln_analysis, threat_intel],
    max_iter=3
)

report_agent = Agent(
    role="Security Report Generator",
    goal="Create comprehensive, professional security assessment reports tailored to technical and executive audiences",
    backstory="""\
You are a technical writing specialist with cybersecurity expertise in:
• Security report writing and documentation standards
• Executive summary creation and risk communication
• Technical finding documentation and evidence presentation
• Compliance mapping and regulatory alignment
• Stakeholder communication across technical and business teams

You transform complex security findings into clear, actionable reports that
drive security improvements and support business decision-making.
    """,
    verbose=True,
    allow_delegation=False,
    llm=groq_llm,
    tools=[],
    max_iter=2
)

# ═══════════════════════════════════════════════════════════════════════════════
# Task Definitions
# ═══════════════════════════════════════════════════════════════════════════════

def create_reconnaissance_task(target_domain):
    return Task(
        description=f"""\
Perform comprehensive reconnaissance and asset discovery for: {target_domain}

Your objectives:
1. **Asset Discovery**: Identify all assets within scope including:
   - Primary domain and subdomains
   - Live services and open ports
   - Infrastructure and technology stack
   - DNS configuration and records

2. **Threat Intelligence**: Analyze the target for:
   - Known security issues or breaches
   - Domain reputation and threat indicators
   - Organizational infrastructure patterns
   - Potential attack vectors

3. **Attack Surface Mapping**: Document:
   - All discovered endpoints and services
   - Technology stack and versions where possible
   - Entry points for security testing
   - Risk factors and priorities

Provide a detailed reconnaissance report with discovered assets categorized by priority level.
Focus on actionable intelligence that will guide the scanning and analysis phases.
        """,
        agent=recon_agent,
        expected_output="""\
Detailed reconnaissance report including:
• Discovered assets list with priorities (High/Medium/Low)
• DNS analysis and infrastructure mapping
• Threat intelligence summary
• Recommended scanning strategy
• Risk assessment of discovered attack surface
        """
    )

def create_scanning_task(recon_results):
    return Task(
        description=f"""\
Based on reconnaissance results, execute comprehensive security scanning:

Reconnaissance Data: {recon_results}

Your objectives:
1. **Scan Planning**: Based on recon results, determine:
   - Optimal scan templates (quick/standard/full) for each target
   - Scan prioritization based on asset criticality
   - Resource allocation and timing

2. **Scan Execution**: Use SentinelAI to perform:
   - Vulnerability scans on high-priority targets
   - Technology-specific security tests
   - Configuration security assessments
   - Network and service enumeration

3. **Scan Coordination**: Manage multiple concurrent scans:
   - Monitor scan progress and results
   - Handle scan failures and retries
   - Optimize scan parameters based on results

4. **Initial Analysis**: Perform basic result processing:
   - Categorize findings by severity
   - Identify obvious false positives
   - Flag critical vulnerabilities for immediate attention

Ensure comprehensive coverage while avoiding scan detection and service disruption.
        """,
        agent=scanner_agent,
        expected_output="""\
Scanning execution report including:
• List of completed scans with status
• Summary of discovered vulnerabilities by severity
• Scan performance metrics and coverage
• Initial finding categorization
• Critical vulnerabilities flagged for immediate review
        """
    )

def create_analysis_task(scan_results):
    return Task(
        description=f"""\
Analyze scanning results to provide expert vulnerability assessment:

Scan Results Data: {scan_results}

Your objectives:
1. **Vulnerability Validation**: For each finding:
   - Assess exploitability and likelihood
   - Verify authenticity (eliminate false positives)
   - Determine business impact and risk level
   - Map to relevant CVE/CWE references

2. **Risk Prioritization**: Prioritize findings based on:
   - CVSS scores and exploit availability
   - Business context and asset criticality
   - Attack complexity and prerequisites
   - Potential impact on confidentiality/integrity/availability

3. **Remediation Planning**: For each validated vulnerability:
   - Provide specific remediation steps
   - Estimate remediation effort and timeline
   - Suggest compensating controls if immediate fixes aren't possible
   - Reference relevant security standards and best practices

4. **Threat Modeling**: Analyze findings in context:
   - Identify attack chains and escalation paths
   - Assess overall security posture
   - Highlight architectural security issues
   - Recommend strategic security improvements

Provide expert analysis that security teams can immediately action.
        """,
        agent=analyst_agent,
        expected_output="""\
Comprehensive vulnerability analysis including:
• Validated vulnerability list with risk scores
• Detailed remediation recommendations for each finding
• Attack chain analysis and exploitation scenarios
• Business risk assessment and impact analysis
• Strategic security recommendations
        """
    )

def create_reporting_task(analysis_results, recon_results):
    return Task(
        description=f"""\
Generate professional security assessment report based on analysis:

Analysis Results: {analysis_results}
Reconnaissance Data: {recon_results}

Your objectives:
1. **Executive Summary**: Create high-level overview including:
   - Key findings and overall risk assessment
   - Business impact summary
   - Strategic recommendations
   - Compliance implications

2. **Technical Report**: Document detailed findings with:
   - Vulnerability descriptions and evidence
   - Risk ratings and CVSS scores
   - Step-by-step remediation instructions
   - Technical details for security teams

3. **Remediation Roadmap**: Provide actionable plan with:
   - Prioritized fix schedule based on risk
   - Resource requirements and timelines
   - Quick wins and long-term improvements
   - Validation and testing recommendations

4. **Appendices**: Include supporting information:
   - Asset inventory and discovery methodology
   - Scan coverage and limitations
   - References to security standards
   - Tool outputs and evidence

Create a professional report suitable for both technical teams and executive leadership.
        """,
        agent=report_agent,
        expected_output="""\
Professional security assessment report containing:
• Executive summary with business risk overview
• Detailed technical findings with remediation steps
• Risk-prioritized remediation roadmap
• Asset inventory and methodology documentation
• Compliance and regulatory considerations
        """
    )

# ═══════════════════════════════════════════════════════════════════════════════
# Crew Definition
# ═══════════════════════════════════════════════════════════════════════════════

class SentinelAICrew:
    def __init__(self):
        self.agents = [recon_agent, scanner_agent, analyst_agent, report_agent]

    def create_crew(self, target_domain):
        """Create a crew for a specific security assessment"""

        # Create tasks
        recon_task = create_reconnaissance_task(target_domain)

        # Tasks that depend on previous results will be created dynamically
        # This is a simplified version - in practice, we'd need better task chaining

        return Crew(
            agents=[recon_agent, scanner_agent, analyst_agent, report_agent],
            tasks=[recon_task],  # Additional tasks will be created based on results
            process=Process.sequential,
            verbose=True,
            manager_llm=groq_llm
        )

    def run_security_assessment(self, target_domain):
        """Run complete autonomous security assessment"""
        try:
            print(f"🚀 Starting autonomous security assessment for: {target_domain}")

            # Phase 1: Reconnaissance
            print("📡 Phase 1: Reconnaissance and Asset Discovery")
            recon_crew = Crew(
                agents=[recon_agent],
                tasks=[create_reconnaissance_task(target_domain)],
                process=Process.sequential,
                verbose=True
            )
            recon_results = recon_crew.kickoff()

            # Phase 2: Scanning
            print("🔍 Phase 2: Security Scanning")
            scanning_crew = Crew(
                agents=[scanner_agent],
                tasks=[create_scanning_task(str(recon_results))],
                process=Process.sequential,
                verbose=True
            )
            scan_results = scanning_crew.kickoff()

            # Phase 3: Analysis
            print("🧠 Phase 3: Vulnerability Analysis")
            analysis_crew = Crew(
                agents=[analyst_agent],
                tasks=[create_analysis_task(str(scan_results))],
                process=Process.sequential,
                verbose=True
            )
            analysis_results = analysis_crew.kickoff()

            # Phase 4: Reporting
            print("📋 Phase 4: Report Generation")
            reporting_crew = Crew(
                agents=[report_agent],
                tasks=[create_reporting_task(str(analysis_results), str(recon_results))],
                process=Process.sequential,
                verbose=True
            )
            final_report = reporting_crew.kickoff()

            print("✅ Security assessment completed successfully!")
            return {
                "target": target_domain,
                "reconnaissance": str(recon_results),
                "scanning": str(scan_results),
                "analysis": str(analysis_results),
                "report": str(final_report)
            }

        except Exception as e:
            print(f"❌ Security assessment failed: {str(e)}")
            return {"error": str(e), "target": target_domain}


# ═══════════════════════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test the security crew
    if not os.getenv("GROQ_API_KEY"):
        print("❌ GROQ_API_KEY environment variable not set!")
        print("Please set your Groq API key: export GROQ_API_KEY='your-key-here'")
        exit(1)

    # Initialize the crew
    crew = SentinelAICrew()

    # Example usage
    target = input("🎯 Enter target domain to assess (e.g., example.com): ").strip()

    if target:
        results = crew.run_security_assessment(target)

        # Save results
        output_file = f"security_assessment_{target.replace('.', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"📁 Results saved to: {output_file}")
    else:
        print("❌ No target specified")