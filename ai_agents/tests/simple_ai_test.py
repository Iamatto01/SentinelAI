#!/usr/bin/env python3
"""
Simple AI Integration Test
Tests core Groq + SentinelAI integration without complex agent setup
"""

import os
import sys
import requests
from dotenv import load_dotenv

# Load environment
load_dotenv()

def test_groq_direct():
    """Test direct Groq API connection"""
    try:
        from groq import Groq

        client = Groq(api_key=os.getenv('GROQ_API_KEY'))
        response = client.chat.completions.create(
            messages=[
                {"role": "user", "content": "Analyze the security domain 'example.com' and provide a brief risk assessment."}
            ],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_tokens=200
        )

        result = response.choices[0].message.content
        print("🎉 Groq AI Integration Test - SUCCESS!")
        print("-" * 50)
        print("AI Security Analysis:")
        print(result)
        print("-" * 50)
        return True
    except Exception as e:
        print(f"❌ Groq test failed: {e}")
        return False

def test_sentinelai_ai_features():
    """Test SentinelAI backend with AI features"""
    try:
        # Test if backend supports AI endpoints

        print("🧠 Testing SentinelAI AI Integration...")

        # For now, just demonstrate the components are working
        from ai_agents.tools import ThreatIntelTool, AssetDiscoveryTool, VulnerabilityAnalysisTool

        # Test Threat Intelligence
        threat_tool = ThreatIntelTool()
        threat_result = threat_tool._run('example.com')
        print("\n✅ Threat Intelligence Analysis:")
        print(threat_result)

        # Test Asset Discovery
        asset_tool = AssetDiscoveryTool()
        asset_result = asset_tool._run('example.com')
        print("\n✅ Asset Discovery:")
        print(asset_result[:300] + "...")

        # Test Vulnerability Analysis
        vuln_tool = VulnerabilityAnalysisTool()
        sample_vulns = "Critical: SQL Injection found in login.php\nHigh: XSS vulnerability in search.php"
        vuln_result = vuln_tool._run(sample_vulns)
        print("\n✅ Vulnerability Analysis:")
        print(vuln_result)

        return True
    except Exception as e:
        print(f"❌ SentinelAI AI features test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🤖 SentinelAI + Groq AI Integration Test")
    print("=" * 60)

    if not os.getenv('GROQ_API_KEY'):
        print("❌ GROQ_API_KEY not set!")
        print("Please run: export GROQ_API_KEY='your_key_here'")
        return False

    print("✅ GROQ_API_KEY configured")

    # Test 1: Direct Groq connection
    groq_ok = test_groq_direct()

    print("\n" + "=" * 60)

    # Test 2: SentinelAI AI features
    sentinel_ok = test_sentinelai_ai_features()

    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)

    if groq_ok and sentinel_ok:
        print("🎉 ALL TESTS PASSED!")
        print("\n✅ Your AI integration is working correctly!")
        print("\n🚀 Ready to use AI-enhanced features:")
        print("   • AI-powered vulnerability analysis")
        print("   • Intelligent asset discovery")
        print("   • Advanced threat intelligence")
        print("   • Smart scan optimization")

        print("\n💡 Next steps:")
        print("   1. Start SentinelAI backend: cd backend && npm run dev")
        print("   2. Access the UI and try AI-enhanced scans")
        print("   3. Test autonomous asset discovery features")

        return True
    else:
        print("❌ Some tests failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)