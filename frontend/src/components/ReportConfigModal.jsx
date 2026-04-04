import { useState, useEffect, useMemo } from 'react';
import { apiFetch, downloadPdfReport } from '../lib/api.js';
import { useToast } from './Toast.jsx';

export default function ReportConfigModal({ open, onClose }) {
  const [type, setType] = useState('full');
  const [selectedId, setSelectedId] = useState('');
  const [scans, setScans] = useState([]);
  const [projects, setProjects] = useState([]);
  const [generating, setGenerating] = useState(false);
  const [aiFirst, setAiFirst] = useState(true);
  const [stage, setStage] = useState('');
  const [error, setError] = useState('');
  const toast = useToast();

  useEffect(() => {
    if (!open) return;
    setError('');
    setGenerating(false);
    setStage('');
    setAiFirst(true);
    Promise.all([apiFetch('/api/scans'), apiFetch('/api/projects')])
      .then(([scanData, projData]) => {
        setScans(scanData?.scans || []);
        setProjects(projData?.projects || []);
      })
      .catch(() => {});
  }, [open]);

  // Reset selection when type changes
  useEffect(() => {
    setSelectedId('');
    setError('');
    setStage('');
  }, [type]);

  const preview = useMemo(() => {
    if (type === 'scan' && selectedId) {
      const scan = scans.find((s) => s.id === selectedId);
      if (scan) {
        return {
          target: scan.target || 'Unknown',
          template: (scan.template || 'standard').charAt(0).toUpperCase() + (scan.template || '').slice(1),
          findings: scan.vulnerabilitiesFound ?? 0,
          status: (scan.status || 'unknown').charAt(0).toUpperCase() + (scan.status || '').slice(1),
        };
      }
    }
    if (type === 'project' && selectedId) {
      const proj = projects.find((p) => p.id === selectedId);
      if (proj) {
        return {
          name: proj.name,
          client: proj.client || 'N/A',
          scanCount: proj.scanCount ?? 0,
          vulnCount: proj.vulnerabilityCount ?? 0,
        };
      }
    }
    if (type === 'full') {
      const totalFindings = scans.reduce((sum, s) => sum + (s.vulnerabilitiesFound ?? 0), 0);
      return {
        totalScans: scans.length,
        totalFindings,
        totalProjects: projects.length,
      };
    }
    return null;
  }, [type, selectedId, scans, projects]);

  const aiTargetScanIds = useMemo(() => {
    if (!aiFirst) return [];
    if (type === 'scan') return selectedId ? [selectedId] : [];
    if (type === 'project') {
      if (!selectedId) return [];
      return scans
        .filter((s) => s.projectId === selectedId && s.id)
        .map((s) => s.id);
    }
    return scans.filter((s) => s.id).map((s) => s.id);
  }, [aiFirst, type, selectedId, scans]);

  async function handleGenerate() {
    if ((type === 'scan' || type === 'project') && !selectedId) {
      setError(`Please select a ${type === 'scan' ? 'scan' : 'project'}`);
      return;
    }
    setGenerating(true);
    setError('');
    try {
      if (aiFirst && aiTargetScanIds.length > 0) {
        let failed = 0;
        for (let i = 0; i < aiTargetScanIds.length; i++) {
          const scanId = aiTargetScanIds[i];
          setStage(`Running AI enhancement (${i + 1}/${aiTargetScanIds.length})...`);
          try {
            await apiFetch(`/api/ai/analyze/${encodeURIComponent(scanId)}`, {
              method: 'POST',
            });
          } catch {
            failed += 1;
          }
        }

        if (failed > 0) {
          toast(`AI enhancement finished with ${failed} skipped/failed scan(s)`);
        }
      }

      setStage('Generating PDF report...');
      await downloadPdfReport(type, selectedId || undefined);
      toast(aiFirst ? 'AI-enhanced PDF report downloaded!' : 'PDF report downloaded!');
      setStage('');
      onClose();
    } catch (err) {
      setStage('');
      setError(err.message);
    } finally {
      setGenerating(false);
    }
  }

  if (!open) return null;

  const types = [
    { id: 'scan', label: 'Single Scan', desc: 'Report for one specific scan' },
    { id: 'project', label: 'Project', desc: 'All scans within a project' },
    { id: 'full', label: 'Full System', desc: 'All scans and findings' },
  ];

  return (
    <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" onClick={onClose}>
      <div className="modal-content w-full max-w-2xl mx-4 rounded-lg p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold">Generate PDF Report</h3>
          <button className="text-gray-400 hover:text-white text-xl" onClick={onClose}>
            &#x2715;
          </button>
        </div>

        <div className="space-y-6">
          {/* Report Type Selection */}
          <div>
            <label className="block text-sm font-medium mb-3">Report Scope</label>
            <div className="grid grid-cols-3 gap-3">
              {types.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className={`p-3 rounded-lg text-left border transition-all ${
                    type === t.id ? 'border-white bg-white/10' : 'border-white/10 hover:border-white/30'
                  }`}
                  onClick={() => setType(t.id)}
                >
                  <p className="font-medium text-sm">{t.label}</p>
                  <p className="text-xs text-gray-400 mt-1">{t.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Scope Selector */}
          {type === 'scan' && (
            <div>
              <label className="block text-sm font-medium mb-2">Select Scan</label>
              <select
                className="search-input w-full px-4 py-3 rounded-lg"
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
              >
                <option value="" className="text-black">-- Select a scan --</option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id} className="text-black">
                    {(s.target || 'unknown').replace(/^https?:\/\//, '').slice(0, 40)} -{' '}
                    {(s.template || 'standard').charAt(0).toUpperCase() + (s.template || '').slice(1)} -{' '}
                    {s.startTime ? new Date(s.startTime).toLocaleDateString() : 'N/A'}
                  </option>
                ))}
              </select>
            </div>
          )}

          {type === 'project' && (
            <div>
              <label className="block text-sm font-medium mb-2">Select Project</label>
              <select
                className="search-input w-full px-4 py-3 rounded-lg"
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
              >
                <option value="" className="text-black">-- Select a project --</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id} className="text-black">
                    {p.name} ({p.client || 'N/A'}) - {p.scanCount ?? 0} scans
                  </option>
                ))}
              </select>
            </div>
          )}

          {type === 'full' && (
            <div className="p-4 bg-white/5 rounded-lg border border-white/10">
              <p className="text-sm text-gray-300">
                The report will include all scans and findings across the entire system.
              </p>
            </div>
          )}

          <label className="flex items-center space-x-3 cursor-pointer p-2 rounded hover:bg-white/5 border border-white/10">
            <input
              type="checkbox"
              className="filter-checkbox"
              checked={aiFirst}
              onChange={(e) => setAiFirst(e.target.checked)}
            />
            <div>
              <span className="text-sm font-medium">AI-enhance findings before report</span>
              <span className="text-xs text-gray-400 ml-2">
                {aiTargetScanIds.length > 0
                  ? `Will run AI analysis on ${aiTargetScanIds.length} scan(s), then generate PDF.`
                  : 'No eligible scans selected yet.'}
              </span>
            </div>
          </label>

          {/* Preview Panel */}
          {preview && (
            <div className="p-4 bg-white/5 rounded-lg border border-white/10">
              <h4 className="text-sm font-medium mb-2 text-gray-300">Report Preview</h4>
              <div className="grid grid-cols-2 gap-2 text-sm">
                {type === 'scan' && preview.target && (
                  <>
                    <span className="text-gray-400">Target:</span>
                    <span className="truncate">{preview.target}</span>
                    <span className="text-gray-400">Template:</span>
                    <span>{preview.template}</span>
                    <span className="text-gray-400">Findings:</span>
                    <span>{preview.findings}</span>
                    <span className="text-gray-400">Status:</span>
                    <span>{preview.status}</span>
                  </>
                )}
                {type === 'project' && preview.name && (
                  <>
                    <span className="text-gray-400">Project:</span>
                    <span>{preview.name}</span>
                    <span className="text-gray-400">Client:</span>
                    <span>{preview.client}</span>
                    <span className="text-gray-400">Scans:</span>
                    <span>{preview.scanCount}</span>
                    <span className="text-gray-400">Findings:</span>
                    <span>{preview.vulnCount}</span>
                  </>
                )}
                {type === 'full' && (
                  <>
                    <span className="text-gray-400">Total Scans:</span>
                    <span>{preview.totalScans}</span>
                    <span className="text-gray-400">Total Projects:</span>
                    <span>{preview.totalProjects}</span>
                    <span className="text-gray-400">Total Findings:</span>
                    <span>{preview.totalFindings}</span>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Report Contents */}
          <div className="p-4 bg-white/5 rounded-lg border border-white/10">
            <h4 className="text-sm font-medium mb-2 text-gray-300">Report Sections</h4>
            <div className="grid grid-cols-2 gap-1 text-xs text-gray-400">
              <span>1. Cover Page</span>
              <span>2. Table of Contents</span>
              <span>3. Executive Summary</span>
              <span>4. Methodology</span>
              <span>5. Findings Summary</span>
              <span>6. Detailed Findings</span>
              <span>7. Appendix</span>
            </div>
          </div>

          {error && <div className="text-red-400 text-sm">{error}</div>}
          {stage && <div className="text-cyan-300 text-sm">{stage}</div>}

          <div className="flex justify-end space-x-4">
            <button
              type="button"
              className="px-6 py-3 border border-white/30 rounded hover:bg-white/10 transition-all"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={generating}
              className="px-6 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium disabled:opacity-50"
              onClick={handleGenerate}
            >
              {generating ? (stage || 'Generating...') : 'Generate Report'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
