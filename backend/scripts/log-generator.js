import fetch from 'node-fetch';

const SENTINEL_URL = process.argv[2] || 'http://localhost:5000/api/logs/ingest';

const SOURCES = ['web-server-1', 'auth-service', 'database-cluster'];
const LEVELS = ['info', 'warning', 'error'];

const MESSAGES = {
  info: [
    'User logged in successfully',
    'Session created for user_123',
    'GET /api/v1/health HTTP/1.1 200',
    'Database connection established',
    'Background job completed successfully'
  ],
  warning: [
    'High memory usage detected',
    'Response time degraded to 2500ms',
    'Rate limit threshold approaching for IP 192.168.1.5',
    'Deprecated API endpoint called'
  ],
  error: [
    'Connection refused by backend service',
    'Failed to authenticate user: Invalid credentials',
    'Timeout while waiting for database query',
    'Cannot read property "id" of undefined',
    'SQL Syntax Error near "DROP TABLE"'
  ]
};

// Simulate a brute force attack (many errors from same IP)
const BRUTE_FORCE_BURST = Array.from({ length: 15 }).map(() => ({
  source: 'auth-service',
  level: 'error',
  message: 'Failed to authenticate user: Invalid credentials (IP: 203.0.113.45)'
}));

// Simulate an out of memory crash
const OOM_BURST = [
  { source: 'web-server-1', level: 'warning', message: 'Memory usage at 90%' },
  { source: 'web-server-1', level: 'warning', message: 'Memory usage at 95%' },
  { source: 'web-server-1', level: 'error', message: 'FATAL: JavaScript heap out of memory' },
  { source: 'web-server-1', level: 'error', message: 'Process crashed with exit code 134' }
];

async function sendLogs(logs) {
  try {
    const res = await fetch(SENTINEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(logs)
    });
    const data = await res.json();
    console.log(`Pushed ${logs.length} logs ->`, data);
  } catch (err) {
    console.error('Failed to push logs:', err.message);
  }
}

function getRandomLog() {
  const source = SOURCES[Math.floor(Math.random() * SOURCES.length)];
  const rand = Math.random();
  // 70% info, 20% warning, 10% error
  const level = rand < 0.7 ? 'info' : (rand < 0.9 ? 'warning' : 'error');
  const msgs = MESSAGES[level];
  const message = msgs[Math.floor(Math.random() * msgs.length)];
  return { source, level, message };
}

async function simulate() {
  console.log(`Starting log simulation targeting ${SENTINEL_URL}`);
  
  // Normal traffic
  for (let i = 0; i < 5; i++) {
    const batch = Array.from({ length: 10 }).map(getRandomLog);
    await sendLogs(batch);
    await new Promise(r => setTimeout(r, 1000));
  }

  console.log('--- Simulating OOM Crash ---');
  await sendLogs(OOM_BURST);
  await new Promise(r => setTimeout(r, 2000));

  // Normal traffic
  for (let i = 0; i < 3; i++) {
    const batch = Array.from({ length: 5 }).map(getRandomLog);
    await sendLogs(batch);
    await new Promise(r => setTimeout(r, 1000));
  }

  console.log('--- Simulating Brute Force Attack ---');
  await sendLogs(BRUTE_FORCE_BURST);
  
  console.log('Done!');
}

simulate();
