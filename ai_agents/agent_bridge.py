#!/usr/bin/env python3
"""
SentinelAI Agent Bridge
HTTP API bridge between Node.js backend and Python CrewAI agents
"""

import os
import json
import asyncio
from flask import Flask, request, jsonify
from flask_cors import CORS
from threading import Thread
import logging
from dotenv import load_dotenv
from security_crew import SentinelAICrew

# Load environment
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize AI crew
ai_crew = SentinelAICrew()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'SentinelAI Agent Bridge',
        'groq_configured': bool(os.getenv('GROQ_API_KEY')),
        'version': '1.0.0'
    })

@app.route('/ai/discover', methods=['POST'])
def discover_assets():
    """Discover assets for a domain using AI agents"""
    try:
        data = request.get_json()
        domain = data.get('domain')

        if not domain:
            return jsonify({'error': 'domain is required'}), 400

        logger.info(f"Starting asset discovery for: {domain}")

        # Use the reconnaissance agent for discovery
        from security_crew import recon_agent, create_reconnaissance_task
        from crewai import Crew

        # Create discovery crew
        discovery_crew = Crew(
            agents=[recon_agent],
            tasks=[create_reconnaissance_task(domain)],
            verbose=True
        )

        # Execute reconnaissance
        result = discovery_crew.kickoff()

        return jsonify({
            'success': True,
            'domain': domain,
            'discovery_results': str(result),
            'status': 'completed'
        })

    except Exception as e:
        logger.error(f"Asset discovery failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ai/analyze', methods=['POST'])
def analyze_vulnerabilities():
    """Analyze vulnerabilities using AI"""
    try:
        data = request.get_json()
        scan_results = data.get('scan_results', {})

        if not scan_results:
            return jsonify({'error': 'scan_results are required'}), 400

        logger.info("Starting AI vulnerability analysis")

        # Use the analyst agent for analysis
        from security_crew import analyst_agent, create_analysis_task
        from crewai import Crew

        # Create analysis crew
        analysis_crew = Crew(
            agents=[analyst_agent],
            tasks=[create_analysis_task(json.dumps(scan_results))],
            verbose=True
        )

        # Execute analysis
        result = analysis_crew.kickoff()

        return jsonify({
            'success': True,
            'analysis_results': str(result),
            'status': 'completed'
        })

    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ai/scan', methods=['POST'])
def coordinate_scan():
    """Coordinate an AI-enhanced security scan"""
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'standard')

        if not target:
            return jsonify({'error': 'target is required'}), 400

        logger.info(f"Coordinating AI scan for: {target}")

        # Use the scanner agent to coordinate
        from security_crew import scanner_agent, create_scanning_task
        from crewai import Crew

        # Mock reconnaissance results for now
        recon_results = f"Target: {target}, Type: {scan_type}"

        # Create scanning crew
        scan_crew = Crew(
            agents=[scanner_agent],
            tasks=[create_scanning_task(recon_results)],
            verbose=True
        )

        # Execute scan coordination
        result = scan_crew.kickoff()

        return jsonify({
            'success': True,
            'target': target,
            'scan_coordination': str(result),
            'status': 'completed'
        })

    except Exception as e:
        logger.error(f"Scan coordination failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ai/report', methods=['POST'])
def generate_report():
    """Generate an AI-enhanced security report"""
    try:
        data = request.get_json()
        analysis_results = data.get('analysis_results', {})
        recon_results = data.get('recon_results', {})

        logger.info("Generating AI-enhanced security report")

        # Use the report agent for reporting
        from security_crew import report_agent, create_reporting_task
        from crewai import Crew

        # Create reporting crew
        report_crew = Crew(
            agents=[report_agent],
            tasks=[create_reporting_task(json.dumps(analysis_results), json.dumps(recon_results))],
            verbose=True
        )

        # Execute report generation
        result = report_crew.kickoff()

        return jsonify({
            'success': True,
            'report': str(result),
            'status': 'completed'
        })

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ai/assessment', methods=['POST'])
def full_assessment():
    """Run a complete autonomous security assessment"""
    try:
        data = request.get_json()
        target_domain = data.get('target_domain')

        if not target_domain:
            return jsonify({'error': 'target_domain is required'}), 400

        logger.info(f"Starting full AI security assessment for: {target_domain}")

        # Run complete assessment
        results = ai_crew.run_security_assessment(target_domain)

        return jsonify({
            'success': True,
            'results': results,
            'status': 'completed'
        })

    except Exception as e:
        logger.error(f"Full assessment failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Check environment
    if not os.getenv('GROQ_API_KEY'):
        logger.warning("GROQ_API_KEY not set! AI features will be limited.")

    # Start the Flask app
    port = int(os.getenv('AI_BRIDGE_PORT', 5001))
    logger.info(f"Starting SentinelAI Agent Bridge on port {port}")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True
    )