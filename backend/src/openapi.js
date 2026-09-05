/**
 * OpenAPI 3.0 specification for the FYP2 Pentest Platform API.
 * Served via swagger-ui-express at /api/docs.
 */

export const openapiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'FYP2 — Unified Pentest Platform API',
    version: '1.0.0',
    description:
      'REST API for the FYP2 AI-powered penetration testing platform. ' +
      'All endpoints except `/api/health` and `/api/auth/login` require a Bearer JWT obtained from `/api/auth/login`.',
    contact: { name: 'FYP2 Security Team' },
  },
  servers: [{ url: '/', description: 'Current server' }],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
    schemas: {
      Error: { type: 'object', properties: { error: { type: 'string' } } },
      Project: {
        type: 'object',
        properties: {
          id: { type: 'string' }, name: { type: 'string' }, client: { type: 'string' },
          scope: { type: 'string' }, created_at: { type: 'string', format: 'date-time' },
        },
      },
      Scan: {
        type: 'object',
        properties: {
          id: { type: 'string' }, target: { type: 'string' }, mode: { type: 'string', enum: ['blackbox', 'whitebox'] },
          template: { type: 'string' }, status: { type: 'string', enum: ['queued', 'running', 'paused', 'completed', 'failed'] },
          progress: { type: 'integer' }, risk_score: { type: 'number' }, project_id: { type: 'string', nullable: true },
          created_at: { type: 'string', format: 'date-time' }, finished_at: { type: 'string', format: 'date-time', nullable: true },
        },
      },
      Finding: {
        type: 'object',
        properties: {
          id: { type: 'string' }, scan_id: { type: 'string' }, title: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          cvss: { type: 'number', nullable: true }, cwe_id: { type: 'string', nullable: true },
          owasp_category: { type: 'string', nullable: true }, description: { type: 'string' },
          remediation: { type: 'string' }, module: { type: 'string' }, status: { type: 'string' },
          ai_agent: { type: 'string', nullable: true }, ai_confidence: { type: 'integer', nullable: true },
        },
      },
      Monitor: {
        type: 'object',
        properties: {
          id: { type: 'string' }, name: { type: 'string' }, target: { type: 'string' },
          interval_minutes: { type: 'integer' }, modules: { type: 'array', items: { type: 'string' } },
          enabled: { type: 'boolean' }, next_run: { type: 'string', format: 'date-time', nullable: true },
        },
      },
    },
  },
  security: [{ bearerAuth: [] }],
  tags: [
    { name: 'System' }, { name: 'Auth' }, { name: 'Projects' }, { name: 'Scans' },
    { name: 'Findings' }, { name: 'Monitors' }, { name: 'Intelligence' }, { name: 'Reports' }, { name: 'Dashboard' },
  ],
  paths: {
    '/api/health': {
      get: {
        tags: ['System'], summary: 'Health check', security: [],
        responses: { 200: { description: 'Server is up' } },
      },
    },
    '/api/status': {
      get: {
        tags: ['System'], summary: 'Engine / RAG / AI status',
        responses: { 200: { description: 'Status object' } },
      },
    },
    '/api/auth/login': {
      post: {
        tags: ['Auth'], summary: 'Login and receive JWT', security: [],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['username', 'password'], properties: { username: { type: 'string' }, password: { type: 'string' } } } } },
        },
        responses: { 200: { description: 'JWT + user' }, 401: { description: 'Invalid credentials' } },
      },
    },
    '/api/users/me': {
      get: { tags: ['Auth'], summary: 'Current user profile', responses: { 200: { description: 'User object' } } },
      put: {
        tags: ['Auth'], summary: 'Update profile',
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { email: { type: 'string' } } } } } },
        responses: { 200: { description: 'Updated' } },
      },
    },
    '/api/users/me/password': {
      post: {
        tags: ['Auth'], summary: 'Change password',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['current', 'next'], properties: { current: { type: 'string' }, next: { type: 'string' } } } } } },
        responses: { 200: { description: 'Password changed' }, 400: { description: 'Wrong current password' } },
      },
    },
    '/api/projects': {
      get: { tags: ['Projects'], summary: 'List projects', responses: { 200: { description: 'Array of projects', content: { 'application/json': { schema: { type: 'array', items: { $ref: '#/components/schemas/Project' } } } } } } },
      post: {
        tags: ['Projects'], summary: 'Create project',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, client: { type: 'string' }, scope: { type: 'string' } } } } } },
        responses: { 200: { description: 'Created project' } },
      },
    },
    '/api/projects/{id}': {
      delete: {
        tags: ['Projects'], summary: 'Delete project',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'Deleted' } },
      },
    },
    '/api/scans': {
      get: { tags: ['Scans'], summary: 'List scans (latest 200)', responses: { 200: { description: 'Array of scans', content: { 'application/json': { schema: { type: 'array', items: { $ref: '#/components/schemas/Scan' } } } } } } },
      post: {
        tags: ['Scans'], summary: 'Start a new scan',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['target', 'mode'], properties: {
            target: { type: 'string', example: 'https://example.com' },
            mode: { type: 'string', enum: ['blackbox', 'whitebox'] },
            template: { type: 'string' }, modules: { type: 'array', items: { type: 'string' } },
            objective: { type: 'string' }, maxTools: { type: 'integer' }, projectId: { type: 'string' },
            files: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } } }, description: 'Whitebox only' },
          } } } },
        },
        responses: { 200: { description: 'Created scan' } },
      },
    },
    '/api/scans/{id}': {
      get: {
        tags: ['Scans'], summary: 'Get scan detail (with findings + logs)',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'Scan detail' }, 404: { description: 'Not found' } },
      },
    },
    '/api/scans/{id}/stop': {
      post: { tags: ['Scans'], summary: 'Stop a running scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Stopped' } } },
    },
    '/api/scans/{id}/pause': {
      post: { tags: ['Scans'], summary: 'Pause a running scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Paused' } } },
    },
    '/api/scans/{id}/resume': {
      post: { tags: ['Scans'], summary: 'Resume a paused scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Resumed' } } },
    },
    '/api/findings': {
      get: {
        tags: ['Findings'], summary: 'List findings',
        parameters: [
          { name: 'scanId', in: 'query', schema: { type: 'string' } },
          { name: 'severity', in: 'query', schema: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] } },
          { name: 'status', in: 'query', schema: { type: 'string' } },
        ],
        responses: { 200: { description: 'Array of findings', content: { 'application/json': { schema: { type: 'array', items: { $ref: '#/components/schemas/Finding' } } } } } },
      },
    },
    '/api/findings/{id}': {
      delete: {
        tags: ['Findings'], summary: 'Delete a finding',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'Deleted' }, 404: { description: 'Not found' } },
      },
    },
    '/api/findings/{id}/status': {
      put: {
        tags: ['Findings'], summary: 'Update finding status',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['status'], properties: { status: { type: 'string', enum: ['open', 'confirmed', 'fixed', 'accepted', 'false-positive'] } } } } } },
        responses: { 200: { description: 'Updated' } },
      },
    },
    '/api/findings/{id}/notes': {
      get: { tags: ['Findings'], summary: 'List finding notes', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Notes' } } },
      post: {
        tags: ['Findings'], summary: 'Add a note to a finding',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['note'], properties: { note: { type: 'string' } } } } } },
        responses: { 200: { description: 'Created note' } },
      },
    },
    '/api/monitors': {
      get: { tags: ['Monitors'], summary: 'List monitors', responses: { 200: { description: 'Array of monitors', content: { 'application/json': { schema: { type: 'array', items: { $ref: '#/components/schemas/Monitor' } } } } } } },
      post: {
        tags: ['Monitors'], summary: 'Create monitor',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name', 'target', 'intervalMinutes'], properties: { name: { type: 'string' }, target: { type: 'string' }, intervalMinutes: { type: 'integer' }, modules: { type: 'array', items: { type: 'string' } } } } } } },
        responses: { 200: { description: 'Created monitor' } },
      },
    },
    '/api/monitors/{id}': {
      get: { tags: ['Monitors'], summary: 'Get monitor', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Monitor' } } },
      put: {
        tags: ['Monitors'], summary: 'Update monitor',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { enabled: { type: 'boolean' }, intervalMinutes: { type: 'integer' } } } } } },
        responses: { 200: { description: 'Updated' } },
      },
      delete: { tags: ['Monitors'], summary: 'Delete monitor', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Deleted' } } },
    },
    '/api/cve/{id}': {
      get: {
        tags: ['Intelligence'], summary: 'CVE details (NVD)',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' }, example: 'CVE-2021-44228' }],
        responses: { 200: { description: 'CVE data' } },
      },
    },
    '/api/agents': {
      get: { tags: ['Intelligence'], summary: 'List AI agent personas', responses: { 200: { description: 'Agent list' } } },
    },
    '/api/agents/chat': {
      post: {
        tags: ['Intelligence'], summary: 'Chat with an AI agent',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['message'], properties: { message: { type: 'string' }, agent: { type: 'string' }, history: { type: 'array', items: { type: 'object' } } } } } } },
        responses: { 200: { description: 'Agent reply' } },
      },
    },
    '/api/payloads/status': {
      get: { tags: ['Intelligence'], summary: 'Payload RAG index status', responses: { 200: { description: 'Status' } } },
    },
    '/api/payloads/reindex': {
      post: { tags: ['Intelligence'], summary: 'Rebuild payload RAG index', responses: { 200: { description: 'Reindexed' } } },
    },
    '/api/payloads/search': {
      get: {
        tags: ['Intelligence'], summary: 'Search payload knowledge base',
        parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'Matching payloads' } },
      },
    },
    '/api/engine/status': {
      get: { tags: ['Intelligence'], summary: 'Native scanner engine status', responses: { 200: { description: 'Engine status' } } },
    },
    '/api/engine/analyze': {
      post: {
        tags: ['Intelligence'], summary: 'AI target analysis',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['target'], properties: { target: { type: 'string' } } } } } },
        responses: { 200: { description: 'Analysis' } },
      },
    },
    '/api/engine/attack-chain': {
      post: {
        tags: ['Intelligence'], summary: 'Generate attack chain',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['target'], properties: { target: { type: 'string' }, objective: { type: 'string' } } } } } },
        responses: { 200: { description: 'Attack chain' } },
      },
    },
    '/api/reports/generate': {
      post: {
        tags: ['Reports'], summary: 'Generate PDF report for a scan',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['scanId'], properties: { scanId: { type: 'string' } } } } } },
        responses: { 200: { description: 'Report generated' } },
      },
    },
    '/api/reports/download/{scanId}': {
      get: {
        tags: ['Reports'], summary: 'Download PDF report',
        parameters: [{ name: 'scanId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'PDF file', content: { 'application/pdf': {} } } },
      },
    },
    '/api/dashboard': {
      get: { tags: ['Dashboard'], summary: 'Dashboard summary stats', responses: { 200: { description: 'Stats' } } },
    },
  },
}

export default openapiSpec
