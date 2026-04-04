# SentinelAI AI Agent Integration Guide

🤖 **Complete deployment guide for SentinelAI + CrewAI + Groq integration**

## 🚀 Overview

This integration adds autonomous AI agents to SentinelAI, providing:

- **24/7 AI-enhanced vulnerability scanning**
- **Autonomous asset discovery and monitoring**
- **Intelligent scan optimization using Groq AI**
- **Advanced vulnerability analysis and prioritization**
- **Automated threat intelligence gathering**

## 📋 Requirements

### Required Dependencies
- **Node.js** 18+ `node --version`
- **Python** 3.12+ `python3 --version`
- **npm/pip** package managers
- **Internet connection** for Groq API

### API Keys (Required)
- **Groq API Key** (Free) - Get at: https://console.groq.com/keys
  - 14,400 free requests per day
  - No GPU hardware required
  - Fast inference with optimized LLMs

### Optional (Recommended)
- **Git** for version control
- **PM2** for production deployment
- **Docker** for containerized deployment

## 🛠️ Installation

### 1. Environment Setup

```bash
# Navigate to SentinelAI directory
cd /path/to/SentinelAI

# Copy environment template
cp .env.example .env

# Edit .env file
nano .env
```

**Critical: Set your Groq API key in .env:**
```bash
GROQ_API_KEY=your_groq_api_key_here
```

### 2. Install Dependencies

```bash
# Install Python AI dependencies
pip3 install -r requirements.txt

# Install Node.js dependencies (if not already done)
cd backend && npm install && cd ..
```

### 3. Verify Installation

```bash
# Run comprehensive test suite
python3 test_ai_integration.py

# Expected output: All tests should pass
```

## 🎯 Quick Start

### Method 1: One-Command Launch (Recommended)
```bash
# Start both backend and AI agents
./start-ai.sh
```

### Method 2: Manual Startup
```bash
# Terminal 1: Start AI Agent Bridge
cd ai_agents
python3 agent_bridge.py

# Terminal 2: Start SentinelAI Backend
cd backend
npm run dev
```

### Access Points
- **Main UI**: http://localhost:5000
- **AI Bridge API**: http://localhost:5001
- **Logs**: `logs/backend.log` and `logs/ai_bridge.log`

## 🧠 AI Features Usage

### 1. AI-Enhanced Scans

**Standard Web UI:**
1. Create/select a project
2. Click "Start AI Scan" instead of "Start Scan"
3. AI automatically optimizes scan parameters
4. Real-time vulnerability analysis during scan

**API Endpoint:**
```bash
curl -X POST http://localhost:5000/api/ai/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "https://example.com",
    "projectId": "proj_123",
    "template": "ai_optimized"
  }'
```

### 2. Autonomous Asset Discovery

**Web UI:**
1. Go to project details
2. Click "AI Asset Discovery"
3. View discovered subdomains and endpoints

**CLI Command:**
```bash
cd ai_agents
python3 autonomous_discovery.py example.com
```

**API Endpoint:**
```bash
curl -X POST http://localhost:5000/api/ai/discover \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"projectId": "proj_123"}'
```

### 3. Advanced Vulnerability Analysis

**Automatic:** AI enhancement runs automatically during scans

**Manual Enhancement:**
```bash
curl -X POST http://localhost:5000/api/ai/analyze/SCAN_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 4. 24/7 Autonomous Monitoring

```bash
# Start continuous asset monitoring
cd ai_agents
python3 autonomous_discovery.py

# Monitors all projects and auto-triggers scans
```

## 📊 AI System Monitoring

### Health Check Endpoints

**Backend AI Status:**
```bash
curl http://localhost:5000/api/ai/status
```

**Agent Bridge Health:**
```bash
curl http://localhost:5001/health
```

### Logs and Debugging
```bash
# View backend logs
tail -f logs/backend.log

# View AI agent logs
tail -f logs/ai_bridge.log

# View autonomous discovery logs
tail -f ai_agents/autonomous_discovery.log
```

## ⚙️ Configuration

### AI Behavior Tuning

**In .env file:**
```bash
# AI system timeouts
AI_SCAN_TIMEOUT=300
AI_MAX_CONCURRENT_SCANS=5
AI_DISCOVERY_CACHE_TTL=3600

# Groq AI model selection (optional)
GROQ_MODEL=llama2-70b-4096
```

### Scan Template Optimization

AI automatically chooses templates based on:
- **Target type** (API, admin panel, staging, etc.)
- **Previous scan history**
- **Business risk level**
- **Client requirements**

### Custom Agent Behavior

**Modify ai_agents/security_crew.py:**
- Adjust agent roles and capabilities
- Add custom tools and integrations
- Modify task prioritization logic

## 🔧 Troubleshooting

### Common Issues

**1. "AI features not available" error**
```bash
# Check Groq API key
echo $GROQ_API_KEY

# Test Groq connection
python3 -c "
from ai_agents.tools import ThreatIntelTool
tool = ThreatIntelTool()
print(tool._run('test.com'))
"
```

**2. Agent bridge connection fails**
```bash
# Check if bridge is running
curl http://localhost:5001/health

# Check bridge logs
tail logs/ai_bridge.log
```

**3. Scans fail with AI enhancement**
```bash
# Run without AI as fallback
curl -X POST http://localhost:5000/api/scan/start \
  -d '{"target": "https://example.com", "template": "standard"}'
```

**4. Python dependency conflicts**
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Performance Optimization

**For high-volume scanning:**
```bash
# Increase AI limits in .env
AI_MAX_CONCURRENT_SCANS=10
AI_SCAN_TIMEOUT=600

# Use faster Groq models for speed
GROQ_MODEL=llama2-7b-4096
```

**For resource-constrained environments:**
```bash
# Reduce AI features
AI_MAX_CONCURRENT_SCANS=2
AI_DISCOVERY_CACHE_TTL=7200
```

## 🔒 Security Considerations

### API Key Security
- Never commit `.env` file to version control
- Use environment variables in production
- Rotate Groq API keys regularly

### Network Security
```bash
# Bind AI bridge to localhost only (default)
AI_BRIDGE_HOST=127.0.0.1

# Use firewall to restrict access
ufw allow from 127.0.0.1 to any port 5001
```

### Data Privacy
- AI agents only process metadata, not sensitive scan data
- Set data retention policies in autonomous discovery
- Groq processes prompts but doesn't store data persistently

## 🚀 Production Deployment

### Using PM2 (Recommended)

```bash
# Install PM2
npm install -g pm2

# Create ecosystem file
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'sentinelai-backend',
    script: 'backend/src/index.js',
    env: {
      NODE_ENV: 'production',
      PORT: 5000
    }
  }, {
    name: 'sentinelai-ai-bridge',
    script: 'ai_agents/agent_bridge.py',
    interpreter: 'python3',
    env: {
      AI_BRIDGE_PORT: 5001
    }
  }]
}
EOF

# Start with PM2
pm2 start ecosystem.config.js
pm2 startup
pm2 save
```

### Using Docker

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM node:18-slim

# Install Python and dependencies
RUN apt-get update && apt-get install -y python3 python3-pip

WORKDIR /app
COPY . .

# Install dependencies
RUN cd backend && npm install
RUN pip3 install -r requirements.txt

EXPOSE 5000 5001

CMD ["./start-ai.sh"]
EOF

# Build and run
docker build -t sentinelai-ai .
docker run -p 5000:5000 -p 5001:5001 sentinelai-ai
```

### Environment Variables for Production

```bash
export NODE_ENV=production
export PORT=5000
export AI_BRIDGE_PORT=5001
export GROQ_API_KEY=your_production_key
export JWT_SECRET=your_secure_jwt_secret
export DATABASE_URL=your_production_db_url
```

## 📈 Scaling and Performance

### Horizontal Scaling
- Deploy multiple AI bridge instances
- Load balance using nginx or HAProxy
- Use Redis for shared caching

### Monitoring Setup
```bash
# Add monitoring endpoints
curl http://localhost:5000/api/ai/status
curl http://localhost:5001/health

# Integrate with monitoring tools (Grafana, etc.)
```

## 🔄 Updates and Maintenance

### Updating AI Components
```bash
# Update Python dependencies
pip3 install -r requirements.txt --upgrade

# Update Node.js dependencies
cd backend && npm update && cd ..

# Test after updates
python3 test_ai_integration.py
```

### Backup and Recovery
```bash
# Backup configuration
cp .env .env.backup
cp -r ai_agents/discovery_results_* backups/

# Database backups (if using Turso)
# Use turso db shell and export commands
```

## 🎯 Best Practices

### 1. Gradual AI Integration
- Start with manual scans + AI analysis
- Enable autonomous discovery for low-priority projects first
- Gradually increase AI automation based on confidence

### 2. Cost Management
- Monitor Groq API usage via dashboard
- Set up usage alerts
- Use caching strategically to reduce API calls

### 3. Quality Assurance
- Regularly review AI-generated findings
- Validate autonomous discovery results
- Maintain feedback loop for AI improvements

## 📞 Support

### Getting Help
1. **Check logs first**: `logs/backend.log` and `logs/ai_bridge.log`
2. **Run test suite**: `python3 test_ai_integration.py`
3. **Verify environment**: Check `.env` configuration
4. **Review documentation**: This guide covers most scenarios

### Useful Commands
```bash
# Quick health check
./start-ai.sh --test

# Reset AI cache
rm -rf ai_agents/__pycache__ ai_agents/*.log

# Manual AI test
python3 test_ai_integration.py --demo
```

---

## 🎉 Congratulations!

You now have a fully functional AI-enhanced SentinelAI system with:

✅ **Autonomous AI agents** powered by CrewAI + Groq
✅ **24/7 asset discovery** and monitoring
✅ **Intelligent vulnerability analysis** and prioritization
✅ **Zero infrastructure requirements** (uses cloud AI)
✅ **Production-ready architecture** with monitoring and scaling

**Ready to revolutionize your security testing! 🚀**