import { scanHeaders } from './headers.js';
import { scanSsl } from './ssl.js';
import { scanPaths } from './paths.js';
import { scanDns } from './dns.js';
import { scanCors } from './cors.js';
import { scanTech } from './tech.js';
import { scanSubdomains } from './subdomains.js';
import { scanInfo } from './info.js';

const MODULE_CONFIG = {
  headers: { name: 'HTTP Headers Analysis', weight: 12, fn: scanHeaders },
  ssl: { name: 'SSL/TLS Analysis', weight: 12, fn: scanSsl },
  paths: { name: 'Exposed Paths Check', weight: 15, fn: scanPaths },
  dns: { name: 'DNS Reconnaissance', weight: 15, fn: scanDns },
  cors: { name: 'CORS Misconfiguration', weight: 12, fn: scanCors },
  tech: { name: 'Technology Detection', weight: 10, fn: scanTech },
  subdomains: { name: 'Subdomain Enumeration', weight: 12, fn: scanSubdomains },
  info: { name: 'Information Disclosure', weight: 12, fn: scanInfo },
};

const TEMPLATE_PRESETS = {
  quick: { headers: true, ssl: true, paths: false, dns: false, cors: false, tech: false, subdomains: false, info: false },
  standard: { headers: true, ssl: true, paths: true, dns: true, cors: true, tech: true, subdomains: false, info: false },
  full: { headers: true, ssl: true, paths: true, dns: true, cors: true, tech: true, subdomains: true, info: true },
};

export function buildModules(selected) {
  const modules = [];
  for (const [key, config] of Object.entries(MODULE_CONFIG)) {
    if (selected?.[key]) {
      modules.push({ name: config.name, key, status: 'queued', progress: 0 });
    }
  }
  return modules;
}

export function getModuleSelection(template, overrides) {
  const preset = TEMPLATE_PRESETS[template] || TEMPLATE_PRESETS.standard;
  return { ...preset, ...overrides };
}

export async function runScan(scanId, target, options, ctx) {
  const { db, io, pushLog, addAudit, saveScan, saveProject, addVuln } = ctx;
  const scan = db.scans.find((s) => s.id === scanId);
  if (!scan) return;

  const selectedModules = getModuleSelection(options.template, options.modules);
  const enabledKeys = Object.keys(selectedModules).filter((k) => selectedModules[k] && MODULE_CONFIG[k]);

  // Calculate total weight for progress
  const totalWeight = enabledKeys.reduce((sum, k) => sum + MODULE_CONFIG[k].weight, 0) || 1;
  let completedWeight = 0;

  // Initialize vulnerabilities storage
  if (!db.vulnerabilitiesByScanId.has(scanId)) {
    db.vulnerabilitiesByScanId.set(scanId, []);
  }

  const emitUpdate = () => {
    const logs = db.scanLogsByScanId.get(scanId) || [];
    io?.to(`scan:${scanId}`).emit('scan:update', {
      scan,
      logs: logs.slice(-50),
    });
  };

  pushLog(scanId, 'info', `Starting scan on target: ${target}`);
  pushLog(scanId, 'info', `Modules enabled: ${enabledKeys.map((k) => MODULE_CONFIG[k].name).join(', ')}`);
  emitUpdate();

  const skippedTools = [];

  for (const key of enabledKeys) {
    const config = MODULE_CONFIG[key];
    const module = scan.modules.find((m) => m.key === key);
    if (!module) continue;

    // Update module status
    module.status = 'running';
    module.progress = 0;
    pushLog(scanId, 'info', `Starting module: ${config.name}`);
    emitUpdate();

    try {
      const onFinding = (finding) => {
        addVuln(scanId, finding);
        const vulns = db.vulnerabilitiesByScanId.get(scanId) || [];
        scan.vulnerabilitiesFound = vulns.length;
        saveScan(scan);
        pushLog(scanId, finding.severity === 'critical' || finding.severity === 'high' ? 'warn' : 'info',
          `[${config.name}] Found: ${finding.title} (${finding.severity})`);
        emitUpdate();
      };

      const onLog = (level, message) => {
        pushLog(scanId, level, `[${config.name}] ${message}`);
        emitUpdate();
      };

      const result = await config.fn(target, onFinding, onLog);

      // Check if tool was skipped
      if (result?.skipped) {
        module.status = 'skipped';
        module.progress = 100;
        pushLog(scanId, 'warn', `${config.name}: skipped - ${result.reason}`);
        skippedTools.push({ name: config.name, reason: result.reason });
      } else {
        module.status = 'completed';
        module.progress = 100;
        const findingCount = Array.isArray(result) ? result.length : 0;
        pushLog(scanId, 'success', `${config.name}: completed with ${findingCount} findings`);
      }
    } catch (err) {
      module.status = 'failed';
      module.progress = 100;
      pushLog(scanId, 'error', `${config.name} failed: ${err.message}`);
    }

    // Update overall progress
    completedWeight += config.weight;
    scan.progress = Math.round((completedWeight / totalWeight) * 100);
    saveScan(scan);
    emitUpdate();
  }

  // Scan complete
  scan.status = 'completed';
  scan.progress = 100;
  scan.endTime = new Date().toISOString();
  saveScan(scan);

  const totalVulns = (db.vulnerabilitiesByScanId.get(scanId) || []).length;
  pushLog(scanId, 'success', `Scan complete. Total findings: ${totalVulns}`);

  if (skippedTools.length > 0) {
    pushLog(scanId, 'warn', `Skipped tools: ${skippedTools.map((t) => `${t.name} (${t.reason})`).join(', ')}`);
  }

  emitUpdate();

  addAudit({
    user: 'system',
    action: 'SCAN_COMPLETED',
    resource: scanId,
    details: `Scan completed with ${totalVulns} findings`,
  });

  // Update associated project counts
  if (scan.projectId) {
    const project = db.projects.find((p) => p.id === scan.projectId);
    if (project) {
      project.scanCount = db.scans.filter((s) => s.projectId === project.id).length;
      project.vulnerabilityCount = (project.vulnerabilityCount || 0) + totalVulns;
      project.updatedAt = new Date().toISOString();
      saveProject(project);
    }
  }
}
