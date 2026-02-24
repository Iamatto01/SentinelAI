import { useState } from 'react';
import { apiFetch } from '../lib/api.js';

function severityColor(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return '#fff';
  if (s === 'high') return '#d1d5db';
  if (s === 'medium') return '#9ca3af';
  if (s === 'low') return '#6b7280';
  return '#4b5563';
}

function severityBadge(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'severity-critical';
  if (s === 'high') return 'severity-high';
  if (s === 'medium') return 'severity-medium';
  if (s === 'low') return 'severity-low';
  return 'severity-info';
}

export default function VulnDetailModal({ open, vuln, onClose, onStatusChange, readOnly = false }) {
  const [newStatus, setNewStatus] = useState('');
  const [updating, setUpdating] = useState(false);

  if (!open || !vuln) return null;

  const sev = (vuln.severity || 'info').toLowerCase();
  const aiPct = Math.round((vuln.aiConfidence || 0) * 100);
  const cvssWidth = ((vuln.cvss || 0) / 10) * 100;

  async function changeStatus(status) {
    setUpdating(true);
    try {
      await apiFetch(`/api/scan/results/${vuln.id}/status`, {
        method: 'PUT',
        body: { status },
      });
      onStatusChange?.(vuln.id, status);
      setNewStatus('');
    } catch {
      // silently fail
    } finally {
      setUpdating(false);
    }
  }

  return (
    <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" onClick={onClose}>
      <div className="modal-content w-full max-w-3xl mx-4 rounded-lg p-6 max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <span className={`${severityBadge(sev)} px-3 py-1 rounded text-sm font-medium`}>
              {sev.toUpperCase()}
            </span>
            <h3 className="text-xl font-bold">{vuln.title || 'Vulnerability Detail'}</h3>
          </div>
          <button className="text-gray-400 hover:text-white text-xl" onClick={onClose}>&#x2715;</button>
        </div>

        <div className="space-y-6">
          {/* CVSS Score Bar */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-300">CVSS Score</span>
              <span className="text-lg font-bold" style={{ color: severityColor(sev) }}>{vuln.cvss ?? 'N/A'}</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-3">
              <div
                className="h-3 rounded-full transition-all"
                style={{ width: `${cvssWidth}%`, backgroundColor: severityColor(sev) }}
              />
            </div>
          </div>

          {/* Key Info Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Status</p>
              <p className="font-medium text-sm">{(vuln.status || 'open').toUpperCase()}</p>
            </div>
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Module</p>
              <p className="font-medium text-sm">{vuln.module || 'Unknown'}</p>
            </div>
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">AI Confidence</p>
              <p className="font-medium text-sm">{aiPct}%</p>
            </div>
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Discovered</p>
              <p className="font-medium text-sm">{vuln.discovered ? new Date(vuln.discovered).toLocaleDateString() : '\u2014'}</p>
            </div>
          </div>

          {/* Asset */}
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Affected Asset</h4>
            <div className="p-3 bg-white/5 rounded-lg font-mono text-sm break-all">{vuln.asset || '\u2014'}</div>
          </div>

          {/* Description */}
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Description</h4>
            <div className="p-4 bg-white/5 rounded-lg text-sm text-gray-200 leading-relaxed">
              {vuln.description || 'No description available.'}
            </div>
          </div>

          {/* AI Reasoning */}
          {vuln.aiReasoning && (
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-2">AI Analysis</h4>
              <div className="p-4 bg-white/5 rounded-lg text-sm text-gray-200 leading-relaxed">
                {vuln.aiReasoning}
              </div>
            </div>
          )}

          {/* Remediation */}
          {vuln.remediation && (
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-2">Remediation</h4>
              <div className="p-4 bg-white/5 rounded-lg text-sm text-gray-200 leading-relaxed border-l-2 border-white/30">
                {vuln.remediation}
              </div>
            </div>
          )}

          {/* References */}
          <div className="flex flex-wrap gap-3">
            {vuln.cweId && (
              <div className="px-3 py-1 bg-white/5 rounded text-xs font-mono">{vuln.cweId}</div>
            )}
            {(vuln.cveIds || []).map((cve) => (
              <div key={cve} className="px-3 py-1 bg-white/5 rounded text-xs font-mono">{cve}</div>
            ))}
          </div>

          {/* Status Change */}
          {!readOnly && (
          <div className="border-t border-white/10 pt-4">
            <h4 className="text-sm font-medium text-gray-300 mb-3">Change Status</h4>
            <div className="flex items-center space-x-3">
              {['open', 'in-progress', 'closed'].map((s) => (
                <button
                  key={s}
                  disabled={updating || (vuln.status || 'open') === s}
                  className={`px-4 py-2 rounded text-sm transition-all ${
                    (vuln.status || 'open') === s
                      ? 'bg-white text-black font-medium'
                      : 'border border-white/20 hover:bg-white/10'
                  } disabled:opacity-50`}
                  onClick={() => changeStatus(s)}
                >
                  {s.replace(/\b\w/g, (c) => c.toUpperCase())}
                </button>
              ))}
            </div>
          </div>
          )}
        </div>

        <div className="flex justify-end mt-6">
          <button
            className="px-6 py-3 border border-white/30 rounded hover:bg-white/10 transition-all"
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
