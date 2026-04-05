#!/usr/bin/env python3
"""
SentinelAI Agent Bridge
HTTP bridge between Node.js backend and Python CrewAI agents.
"""

import os
import sys
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# ── Fix import path so this works whether launched from root OR ai_agents/ ──
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

load_dotenv()

from security_crew import SentinelAICrew

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
)
logger = logging.getLogger('agent_bridge')

ai_crew = SentinelAICrew()

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'service': 'SentinelAI Agent Bridge',
        'groq_configured': bool(os.getenv('GROQ_API_KEY')),
        'version': '1.1.0',
    })


# ---------------------------------------------------------------------------
# Asset discovery
# ---------------------------------------------------------------------------

@app.route('/ai/discover', methods=['POST'])
def discover_assets():
    try:
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', '').strip()
        if not domain:
            return jsonify({'error': 'domain is required'}), 400

        logger.info(f"Asset discovery → {domain}")

        from security_crew import recon_agent, create_reconnaissance_task
        from crewai import Crew, Process

        crew = Crew(
            agents=[recon_agent],
            tasks=[create_reconnaissance_task(domain)],
            process=Process.sequential,
            verbose=False,
        )
        result = crew.kickoff()

        return jsonify({
            'success': True,
            'domain': domain,
            'discovery_results': str(result),
            'status': 'completed',
        })

    except Exception as e:
        logger.error(f"Asset discovery failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Vulnerability analysis
# ---------------------------------------------------------------------------

@app.route('/ai/analyze', methods=['POST'])
def analyze_vulnerabilities():
    try:
        data = request.get_json(silent=True) or {}
        scan_results = data.get('scan_results', {})
        if not scan_results:
            return jsonify({'error': 'scan_results are required'}), 400

        logger.info("Vulnerability analysis requested")

        from security_crew import analyst_agent, create_analysis_task
        from crewai import Crew, Process

        crew = Crew(
            agents=[analyst_agent],
            tasks=[create_analysis_task(json.dumps(scan_results))],
            process=Process.sequential,
            verbose=False,
        )
        result = crew.kickoff()

        return jsonify({
            'success': True,
            'analysis_results': str(result),
            'status': 'completed',
        })

    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Scan coordination
# ---------------------------------------------------------------------------

@app.route('/ai/scan', methods=['POST'])
def coordinate_scan():
    try:
        data = request.get_json(silent=True) or {}
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'standard')
        if not target:
            return jsonify({'error': 'target is required'}), 400

        logger.info(f"Scan coordination → {target} ({scan_type})")

        from security_crew import scanner_agent, create_scanning_task
        from crewai import Crew, Process

        recon_context = f"Target: {target}, Type: {scan_type}"
        crew = Crew(
            agents=[scanner_agent],
            tasks=[create_scanning_task(recon_context)],
            process=Process.sequential,
            verbose=False,
        )
        result = crew.kickoff()

        return jsonify({
            'success': True,
            'target': target,
            'scan_coordination': str(result),
            'status': 'completed',
        })

    except Exception as e:
        logger.error(f"Scan coordination failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

@app.route('/ai/report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json(silent=True) or {}
        analysis_results = data.get('analysis_results', {})
        recon_results    = data.get('recon_results', {})

        logger.info("Report generation requested")

        from security_crew import report_agent, create_reporting_task
        from crewai import Crew, Process

        crew = Crew(
            agents=[report_agent],
            tasks=[create_reporting_task(
                json.dumps(analysis_results),
                json.dumps(recon_results),
            )],
            process=Process.sequential,
            verbose=False,
        )
        result = crew.kickoff()

        return jsonify({
            'success': True,
            'report': str(result),
            'status': 'completed',
        })

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Full autonomous assessment
# ---------------------------------------------------------------------------

@app.route('/ai/assessment', methods=['POST'])
def full_assessment():
    try:
        data = request.get_json(silent=True) or {}
        target_domain = data.get('target_domain', '').strip()
        if not target_domain:
            return jsonify({'error': 'target_domain is required'}), 400

        logger.info(f"Full assessment → {target_domain}")
        results = ai_crew.run_security_assessment(target_domain)

        return jsonify({
            'success': True,
            'results': results,
            'status': 'completed',
        })

    except Exception as e:
        logger.error(f"Full assessment failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    if not os.getenv('GROQ_API_KEY'):
        logger.warning("GROQ_API_KEY not set — AI features will be limited.")

    port = int(os.getenv('AI_BRIDGE_PORT', 5001))
    logger.info(f"Starting SentinelAI Agent Bridge on port {port}")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True,
    )
