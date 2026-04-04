#!/bin/bash

# SentinelAI with AI Agents - Startup Script
# Launches both Node.js backend and Python AI agent bridge

set -e

echo "🚀 Starting SentinelAI with AI Agent Integration..."

# Load .env values into process environment when present.
# Use a safe parser (not `source`) so regex/special chars in values are kept literal.
if [ -f ".env" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and blank lines
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Keep only KEY=VALUE entries
        [[ "$line" != *"="* ]] && continue

        key="${line%%=*}"
        value="${line#*=}"

        # Trim surrounding whitespace from key only
        key="${key##[[:space:]]}"
        key="${key%%[[:space:]]}"

        export "$key=$value"
    done < .env
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is available
port_available() {
    ! nc -z localhost "$1" 2>/dev/null
}

# Check dependencies
echo -e "${BLUE}🔍 Checking dependencies...${NC}"

if ! command_exists node; then
    echo -e "${RED}❌ Node.js is not installed${NC}"
    exit 1
fi

if ! command_exists python3; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    exit 1
fi

if ! command_exists npm; then
    echo -e "${RED}❌ npm is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Dependencies check passed${NC}"

# Check environment variables
echo -e "${BLUE}🔧 Checking environment...${NC}"

if [ -z "$GROQ_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  GROQ_API_KEY not set. AI features will be limited.${NC}"
    echo -e "${YELLOW}   Get your free API key at: https://console.groq.com/keys${NC}"
else
    echo -e "${GREEN}✅ GROQ_API_KEY configured${NC}"
fi

# Check ports
BACKEND_PORT=${PORT:-5000}
BRIDGE_PORT=${AI_BRIDGE_PORT:-5001}

if ! port_available $BACKEND_PORT; then
    echo -e "${RED}❌ Port $BACKEND_PORT is already in use${NC}"
    exit 1
fi

if ! port_available $BRIDGE_PORT; then
    echo -e "${RED}❌ Port $BRIDGE_PORT is already in use${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Ports $BACKEND_PORT and $BRIDGE_PORT are available${NC}"

# Install Node.js dependencies if needed
if [ ! -d "backend/node_modules" ]; then
    echo -e "${BLUE}📦 Installing Node.js dependencies...${NC}"
    cd backend && npm install && cd ..
fi

# Install Python dependencies if needed
echo -e "${BLUE}🐍 Checking Python dependencies...${NC}"
pip3 install -r requirements.txt -q

# Create log directories
mkdir -p logs

echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""

# Function to cleanup background processes
cleanup() {
    echo -e "\n${YELLOW}🛑 Shutting down services...${NC}"
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
        echo -e "${GREEN}✅ Backend stopped${NC}"
    fi
    if [ ! -z "$BRIDGE_PID" ]; then
        kill $BRIDGE_PID 2>/dev/null
        echo -e "${GREEN}✅ AI bridge stopped${NC}"
    fi
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup INT TERM EXIT

# Start Python AI Agent Bridge
echo -e "${BLUE}🐍 Starting AI Agent Bridge on port $BRIDGE_PORT...${NC}"
cd ai_agents
python3 agent_bridge.py > ../logs/ai_bridge.log 2>&1 &
BRIDGE_PID=$!
cd ..

# Wait a moment for the bridge to start
for i in {1..30}; do
    if nc -z localhost $BRIDGE_PORT 2>/dev/null; then
        break
    fi
    sleep 1
done

# Check if bridge started successfully
if ! nc -z localhost $BRIDGE_PORT 2>/dev/null; then
    echo -e "${RED}❌ AI Agent Bridge failed to start${NC}"
    echo -e "${RED}   Check logs/ai_bridge.log for details${NC}"
    exit 1
fi

echo -e "${GREEN}✅ AI Agent Bridge started (PID: $BRIDGE_PID)${NC}"

# Start Node.js Backend
echo -e "${BLUE}🚀 Starting SentinelAI Backend on port $BACKEND_PORT...${NC}"
cd backend
npm run dev > ../logs/backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait a moment for backend to start
for i in {1..30}; do
    if nc -z localhost $BACKEND_PORT 2>/dev/null; then
        break
    fi
    sleep 1
done

# Check if backend started successfully
if ! nc -z localhost $BACKEND_PORT 2>/dev/null; then
    echo -e "${RED}❌ SentinelAI Backend failed to start${NC}"
    echo -e "${RED}   Check logs/backend.log for details${NC}"
    exit 1
fi

echo -e "${GREEN}✅ SentinelAI Backend started (PID: $BACKEND_PID)${NC}"

# Display status
echo ""
echo -e "${GREEN}🎉 SentinelAI with AI Agents is now running!${NC}"
echo ""
echo -e "${BLUE}📊 Service Status:${NC}"
echo -e "   • Backend API:    http://localhost:$BACKEND_PORT"
echo -e "   • AI Agent Bridge: http://localhost:$BRIDGE_PORT"
echo -e "   • Frontend:       http://localhost:$BACKEND_PORT"
echo ""
echo -e "${BLUE}📁 Logs:${NC}"
echo -e "   • Backend:        logs/backend.log"
echo -e "   • AI Bridge:      logs/ai_bridge.log"
echo ""
echo -e "${YELLOW}💡 AI Features Available:${NC}"
if [ ! -z "$GROQ_API_KEY" ]; then
    echo -e "   ✅ AI-enhanced vulnerability scanning"
    echo -e "   ✅ Autonomous asset discovery"
    echo -e "   ✅ Intelligent scan optimization"
    echo -e "   ✅ Advanced vulnerability analysis"
else
    echo -e "   ⚠️  Limited - Set GROQ_API_KEY for full AI features"
fi
echo ""
echo -e "${GREEN}🔥 Ready for security testing!${NC}"
echo -e "${BLUE}Press Ctrl+C to stop all services${NC}"
echo ""

# Monitor services and display logs
while true; do
    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        echo -e "${RED}❌ Backend process died${NC}"
        break
    fi
    if ! kill -0 $BRIDGE_PID 2>/dev/null; then
        echo -e "${RED}❌ AI Bridge process died${NC}"
        break
    fi
    sleep 5
done