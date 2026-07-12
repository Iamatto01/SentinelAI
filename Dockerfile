# ═══════════════════════════════════════════════════════════════════════════════
# SentinelAI — Multi-Stage Dockerfile
#
# Usage:
#   docker compose up --build          (recommended — uses docker-compose.yml)
#   docker build --target backend .    (build backend image only)
#   docker build --target ai-bridge .  (build AI bridge image only)
# ═══════════════════════════════════════════════════════════════════════════════


# ─── Stage 1: Build the React Frontend ────────────────────────────────────────

FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend

# Install frontend dependencies
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install

# Copy frontend source and build
COPY frontend/ ./
RUN npm run build


# ─── Stage 2: Backend (Node.js) — serves API + built frontend ────────────────

FROM node:20-alpine AS backend

WORKDIR /app

# Install pentesting tools (Nmap, Nikto, Nuclei) so the backend can execute them
RUN apk update && apk add --no-cache \
    nmap \
    nmap-scripts \
    curl \
    bind-tools \
    perl \
    perl-net-ssleay \
    unzip \
    && wget https://github.com/sullo/nikto/archive/master.zip \
    && unzip master.zip && mv nikto-main/program /opt/nikto \
    && rm -rf master.zip nikto-main \
    && ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto \
    && wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip \
    && unzip nuclei_3.3.2_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.2_linux_amd64.zip

# Install backend dependencies
COPY backend/package.json backend/package-lock.json* ./backend/
RUN cd backend && (npm install --frozen-lockfile 2>/dev/null || npm install) && cd ..

# Copy backend source
COPY backend/src/ ./backend/src/

# Copy built frontend from Stage 1
COPY --from=frontend-build /app/frontend/dist ./frontend/dist/



# The backend reads .env via --env-file flag, but in Docker we pass env vars
# through docker-compose, so we use a simple start command
ENV NODE_ENV=production
ENV PORT=5000
ENV AI_BRIDGE_URL=http://ai-bridge:5001

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

CMD ["node", "backend/src/index.js"]


# ─── Stage 3: AI Bridge (Python) ─────────────────────────────────────────────

FROM python:3.11-slim AS ai-bridge

WORKDIR /app

# Install system dependencies needed by some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy AI agent code
COPY ai_agents/ ./ai_agents/

ENV PYTHONUNBUFFERED=1
ENV AI_BRIDGE_PORT=5001

EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

CMD ["python3", "ai_agents/agent_bridge.py"]
