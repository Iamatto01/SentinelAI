#!/usr/bin/env python3
"""
SentinelAI Autonomous Asset Discovery
Continuous monitoring and discovery of client assets
"""

import os
import json
import time
import asyncio
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from security_crew import SentinelAICrew
import requests

# Load environment
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('autonomous_discovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AutonomousDiscoveryAgent:
    def __init__(self):
        self.crew = SentinelAICrew()
        self.discovery_interval = 3600  # 1 hour
        self.backend_url = "http://localhost:5000"
        self.projects_cache = {}
        self.last_discovery = {}

    def should_discover_project(self, project_id, scope):
        """Determine if project needs asset discovery"""
        # Check if enough time has passed since last discovery
        last_time = self.last_discovery.get(project_id, 0)
        time_since_last = time.time() - last_time

        if time_since_last < self.discovery_interval:
            return False

        # Check if project has scope defined
        if not scope or scope.strip() == '':
            return False

        return True

    def get_active_projects(self):
        """Fetch active projects from SentinelAI backend"""
        try:
            # For autonomous operation, we'll simulate project data
            # In production, this would fetch from the API with service account
            projects = [
                {
                    "id": "proj_demo",
                    "name": "Demo Security Assessment",
                    "client": "Demo Corp",
                    "scope": "example.com",
                    "status": "active"
                }
            ]
            return projects
        except Exception as e:
            logger.error(f"Failed to fetch projects: {e}")
            return []

    async def discover_assets_for_project(self, project):
        """Perform asset discovery for a specific project"""
        try:
            project_id = project['id']
            project_name = project['name']
            scope = project['scope']

            logger.info(f"🔍 Starting asset discovery for {project_name} ({scope})")

            # Extract domains from scope
            domains = [s.strip() for s in scope.split(',')]
            all_assets = []

            for domain in domains:
                logger.info(f"🌐 Discovering assets for domain: {domain}")

                # Use AI agents for discovery
                discovery_results = await self.discover_domain_assets(domain)

                # Process and categorize results
                processed_assets = self.process_discovery_results(discovery_results, domain)
                all_assets.extend(processed_assets)

                logger.info(f"✅ Found {len(processed_assets)} assets for {domain}")

            # Update last discovery time
            self.last_discovery[project_id] = time.time()

            # Save results
            self.save_discovery_results(project_id, project_name, all_assets)

            # Trigger high-priority scans if critical assets found
            await self.trigger_priority_scans(project_id, all_assets)

            logger.info(f"🎯 Discovery completed for {project_name}: {len(all_assets)} total assets")
            return all_assets

        except Exception as e:
            logger.error(f"Asset discovery failed for project {project['name']}: {e}")
            return []

    async def discover_domain_assets(self, domain):
        """Use AI agents to discover assets for a domain"""
        try:
            # Use the reconnaissance agent
            from security_crew import recon_agent, create_reconnaissance_task
            from crewai import Crew

            logger.info(f"🤖 AI agent discovery for {domain}")

            # Create reconnaissance crew
            recon_crew = Crew(
                agents=[recon_agent],
                tasks=[create_reconnaissance_task(domain)],
                verbose=False  # Reduce noise in autonomous mode
            )

            # Execute discovery
            result = recon_crew.kickoff()
            return str(result)

        except Exception as e:
            logger.error(f"AI agent discovery failed for {domain}: {e}")
            return f"Domain: {domain}\nBasic discovery completed"

    def process_discovery_results(self, results, domain):
        """Process raw discovery results into structured asset data"""
        assets = []

        try:
            # Extract URLs and endpoints
            import re

            # Find HTTP/HTTPS URLs
            url_pattern = r'https?://[^\s<>"\[\]{}]*'
            urls = re.findall(url_pattern, results)

            for url in urls:
                assets.append({
                    'url': url,
                    'type': self.classify_asset(url),
                    'priority': self.calculate_priority(url),
                    'discovered_at': datetime.now().isoformat(),
                    'source': 'ai_agent',
                    'domain': domain
                })

            # Find domain names and subdomains
            subdomain_pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(domain)
            subdomains = re.findall(subdomain_pattern, results, re.IGNORECASE)

            for subdomain in set(subdomains):  # Remove duplicates
                if subdomain not in [asset['url'] for asset in assets]:
                    assets.append({
                        'url': f'https://{subdomain}',
                        'type': self.classify_asset(subdomain),
                        'priority': self.calculate_priority(subdomain),
                        'discovered_at': datetime.now().isoformat(),
                        'source': 'ai_agent',
                        'domain': domain
                    })

            # If no specific assets found, add the main domain
            if not assets:
                assets.append({
                    'url': f'https://{domain}',
                    'type': 'web',
                    'priority': 'medium',
                    'discovered_at': datetime.now().isoformat(),
                    'source': 'ai_agent',
                    'domain': domain
                })

        except Exception as e:
            logger.error(f"Error processing discovery results: {e}")

        return assets[:10]  # Limit to prevent overwhelming

    def classify_asset(self, url_or_domain):
        """Classify asset type based on URL or domain"""
        text = url_or_domain.lower()

        if 'api.' in text or '/api/' in text:
            return 'api'
        elif 'admin.' in text or '/admin' in text:
            return 'admin'
        elif any(word in text for word in ['staging', 'dev', 'test']):
            return 'staging'
        elif 'mail.' in text or 'email.' in text:
            return 'mail'
        else:
            return 'web'

    def calculate_priority(self, url_or_domain):
        """Calculate asset priority for scanning"""
        text = url_or_domain.lower()

        if any(word in text for word in ['admin', 'login', 'auth']):
            return 'critical'
        elif any(word in text for word in ['api', 'service']):
            return 'high'
        elif any(word in text for word in ['staging', 'dev']):
            return 'medium'
        else:
            return 'low'

    def save_discovery_results(self, project_id, project_name, assets):
        """Save discovery results to file"""
        try:
            results = {
                'project_id': project_id,
                'project_name': project_name,
                'discovery_time': datetime.now().isoformat(),
                'assets_count': len(assets),
                'assets': assets
            }

            filename = f"discovery_results_{project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)

            logger.info(f"💾 Discovery results saved to {filename}")

        except Exception as e:
            logger.error(f"Failed to save discovery results: {e}")

    async def trigger_priority_scans(self, project_id, assets):
        """Trigger automated scans for high-priority assets"""
        try:
            critical_assets = [a for a in assets if a['priority'] == 'critical']
            high_assets = [a for a in assets if a['priority'] == 'high']

            priority_assets = critical_assets + high_assets[:3]  # Max 3 high priority

            if priority_assets:
                logger.info(f"🚨 Triggering automated scans for {len(priority_assets)} priority assets")

                for asset in priority_assets:
                    # In a real implementation, this would call the SentinelAI API
                    logger.info(f"🔍 Would auto-scan: {asset['url']} (Priority: {asset['priority']})")

                    # Simulate scan trigger
                    await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Failed to trigger priority scans: {e}")

    async def monitoring_loop(self):
        """Main monitoring loop for autonomous discovery"""
        logger.info("🤖 Starting autonomous asset discovery monitoring")

        while True:
            try:
                logger.info("🔄 Checking for projects requiring asset discovery...")

                projects = self.get_active_projects()
                logger.info(f"📊 Found {len(projects)} active projects")

                for project in projects:
                    if self.should_discover_project(project['id'], project['scope']):
                        await self.discover_assets_for_project(project)
                    else:
                        logger.debug(f"⏭️  Skipping {project['name']} (recently discovered)")

                logger.info(f"💤 Sleeping for {self.discovery_interval} seconds until next discovery cycle")
                await asyncio.sleep(self.discovery_interval)

            except KeyboardInterrupt:
                logger.info("🛑 Autonomous discovery stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying

    async def run_single_discovery(self, domain):
        """Run a single discovery for testing purposes"""
        logger.info(f"🎯 Running single asset discovery for: {domain}")

        project = {
            'id': f'test_{int(time.time())}',
            'name': f'Test Discovery - {domain}',
            'scope': domain
        }

        assets = await self.discover_assets_for_project(project)

        print(f"\n🎉 Discovery Results for {domain}:")
        print(f"Total Assets Found: {len(assets)}")

        for asset in assets:
            print(f"  • {asset['url']} ({asset['type']}) - Priority: {asset['priority']}")

        return assets

async def main():
    """Main entry point"""
    discovery_agent = AutonomousDiscoveryAgent()

    # Check if we should run in test mode
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        await discovery_agent.run_single_discovery(domain)
    else:
        # Run continuous monitoring
        await discovery_agent.monitoring_loop()

if __name__ == "__main__":
    # Check environment
    if not os.getenv('GROQ_API_KEY'):
        logger.warning("⚠️  GROQ_API_KEY not set. AI features will be limited.")
        print("Get your free API key at: https://console.groq.com/keys")
        print("Then set it: export GROQ_API_KEY='your-key-here'")

    print("🤖 SentinelAI Autonomous Asset Discovery")
    print("Usage:")
    print("  python3 autonomous_discovery.py                # Continuous monitoring")
    print("  python3 autonomous_discovery.py example.com    # Single discovery test")
    print()

    asyncio.run(main())