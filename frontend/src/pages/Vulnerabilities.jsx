import { useEffect, useMemo, useState } from 'react';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import ActionMenu from '../components/ActionMenu.jsx';
import VulnDetailModal from '../components/VulnDetailModal.jsx';
import StatusPickerModal from '../components/StatusPickerModal.jsx';
import { apiFetch } from '../lib/api.js';

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function severityBadge(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'severity-critical';
  if (s === 'high') return 'severity-high';
  if (s === 'medium') return 'severity-medium';
  if (s === 'low') return 'severity-low';
  return 'severity-info';
}

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'open') return 'status-open';
  if (s === 'in progress' || s === 'in-progress') return 'status-in-progress';
  if (s === 'closed') return 'status-closed';
  return 'status-open';
}

export default function Vulnerabilities() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [vulns, setVulns] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('severity');
  const [viewMode, setViewMode] = useState('table');
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [showStatusPicker, setShowStatusPicker] = useState(false);

  const [severityFilter, setSeverityFilter] = useState({
    critical: true,
    high: true,
    medium: true,
    low: true,
    info: true,
  });
  const [statusFilter, setStatusFilter] = useState({
    open: true,
    'in-progress': true,
    closed: false,
  });

  const toast = useToast();

  async function loadVulns() {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/api/vulnerabilities');
      setVulns(data?.vulnerabilities || []);
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadVulns();
  }, []);

  const filtered = useMemo(() => {
    return vulns
      .filter((v) => {
        const sev = (v.severity || 'info').toLowerCase();
        if (!severityFilter[sev]) return false;
        const st = (v.status || 'open').toLowerCase().replace(/ /g, '-');
        if (!statusFilter[st]) return false;
        if (searchTerm) {
          const term = searchTerm.toLowerCase();
          const title = (v.title || '').toLowerCase();
          const asset = (v.asset || '').toLowerCase();
          if (!title.includes(term) && !asset.includes(term)) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'severity') {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (order[(a.severity || 'info').toLowerCase()] ?? 4) - (order[(b.severity || 'info').toLowerCase()] ?? 4);
        }
        if (sortBy === 'status') return (a.status || '').localeCompare(b.status || '');
        if (sortBy === 'asset') return (a.asset || '').localeCompare(b.asset || '');
        if (sortBy === 'cvss') return (b.cvss || 0) - (a.cvss || 0);
        return 0;
      });
  }, [vulns, searchTerm, sortBy, severityFilter, statusFilter]);

  const counts = useMemo(() => {
    const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const st = { open: 0, 'in-progress': 0, closed: 0 };
    const assets = {};
    vulns.forEach((v) => {
      const s = (v.severity || 'info').toLowerCase();
      if (sev[s] !== undefined) sev[s]++;
      const status = (v.status || 'open').toLowerCase().replace(/ /g, '-');
      if (st[status] !== undefined) st[status]++;
      const asset = v.asset || 'unknown';
      assets[asset] = (assets[asset] || 0) + 1;
    });
    return { sev, st, assets };
  }, [vulns]);

  function toggleSelectAll() {
    if (selectedIds.size === filtered.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((v) => v.id)));
    }
  }

  function toggleSelect(id) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function clearFilters() {
    setSeverityFilter({ critical: true, high: true, medium: true, low: true, info: true });
    setStatusFilter({ open: true, 'in-progress': true, closed: true });
    setSearchTerm('');
    toast('All filters cleared');
  }

  function handleVulnStatusChange(vulnId, status) {
    setVulns((prev) => prev.map((v) => (v.id === vulnId ? { ...v, status } : v)));
    setSelectedVuln((prev) => (prev && prev.id === vulnId ? { ...prev, status } : prev));
    toast(`Status updated to ${status}`);
  }

  function handleBulkStatusDone(status) {
    setVulns((prev) =>
      prev.map((v) => (selectedIds.has(v.id) ? { ...v, status } : v))
    );
    setSelectedIds(new Set());
    toast(`Bulk status update to ${status} complete`);
  }

  function exportCSV() {
    const ids = selectedIds.size > 0 ? selectedIds : new Set(filtered.map((v) => v.id));
    const toExport = vulns.filter((v) => ids.has(v.id));
    const header = 'Title,Severity,CVSS,Status,Asset,Module,CWE,Description\n';
    const rows = toExport
      .map((v) =>
        [
          `"${(v.title || '').replace(/"/g, '""')}"`,
          v.severity || '',
          v.cvss ?? '',
          v.status || '',
          `"${(v.asset || '').replace(/"/g, '""')}"`,
          v.module || '',
          v.cweId || '',
          `"${(v.description || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`,
        ].join(',')
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Exported ${toExport.length} vulnerabilities`);
  }

  const allSelected = filtered.length > 0 && selectedIds.size === filtered.length;

  function renderTable() {
    return (
      <div className="glassmorphism rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-white/5 border-b border-white/10">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                <input
                  type="checkbox"
                  className="filter-checkbox"
                  checked={allSelected}
                  onChange={toggleSelectAll}
                />
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Vulnerability</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Asset</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">CVSS</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">AI Confidence</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {filtered.map((v) => {
              const sev = (v.severity || 'info').toLowerCase();
              const status = (v.status || 'open').toLowerCase();
              const aiPct = clamp(Math.round((v.aiConfidence || 0) * 100), 0, 100);
              const aiClass = aiPct >= 90 ? 'ai-high' : aiPct >= 70 ? 'ai-medium' : 'ai-low';
              return (
                <tr
                  key={v.id}
                  className="vulnerability-row cursor-pointer"
                  onClick={() => setSelectedVuln(v)}
                >
                  <td className="px-6 py-4" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      className="filter-checkbox"
                      checked={selectedIds.has(v.id)}
                      onChange={() => toggleSelect(v.id)}
                    />
                  </td>
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium">{v.title || 'Untitled finding'}</p>
                      <p className="text-sm text-gray-400 truncate max-w-xs">{v.module || ''}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`${severityBadge(sev)} px-2 py-1 rounded text-xs`}>
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm max-w-xs truncate">{v.asset || '\u2014'}</td>
                  <td className="px-6 py-4">
                    <span className={`${statusBadge(status)} px-2 py-1 rounded text-xs`}>
                      {status.replace(/\b\w/g, (c) => c.toUpperCase())}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm">{v.cvss ?? '\u2014'}</td>
                  <td className="px-6 py-4 text-sm">
                    <span className={aiClass}>{aiPct}%</span>
                  </td>
                  <td className="px-6 py-4" onClick={(e) => e.stopPropagation()}>
                    <ActionMenu
                      items={[
                        { label: 'View Details', onClick: () => setSelectedVuln(v) },
                        { label: 'Export as CSV', onClick: () => { setSelectedIds(new Set([v.id])); exportCSV(); } },
                      ]}
                    />
                  </td>
                </tr>
              );
            })}
            {!loading && filtered.length === 0 ? (
              <tr>
                <td className="px-6 py-4 text-gray-400" colSpan={8}>
                  No vulnerabilities match filters.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    );
  }

  function renderCards() {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filtered.map((v) => {
          const sev = (v.severity || 'info').toLowerCase();
          const status = (v.status || 'open').toLowerCase();
          const aiPct = clamp(Math.round((v.aiConfidence || 0) * 100), 0, 100);
          return (
            <div
              key={v.id}
              className="card-hover p-6 rounded-lg cursor-pointer"
              onClick={() => setSelectedVuln(v)}
            >
              <div className="flex items-center justify-between mb-3">
                <span className={`${severityBadge(sev)} px-2 py-1 rounded text-xs`}>
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                </span>
                <span className={`${statusBadge(status)} px-2 py-1 rounded text-xs`}>
                  {status.replace(/\b\w/g, (c) => c.toUpperCase())}
                </span>
              </div>
              <h4 className="font-semibold mb-2">{v.title || 'Untitled finding'}</h4>
              <p className="text-xs text-gray-400 mb-3 line-clamp-2">{v.description || ''}</p>
              <div className="flex justify-between text-xs text-gray-400">
                <span className="truncate max-w-[150px]">{v.asset || '\u2014'}</span>
                <span>CVSS: {v.cvss ?? '\u2014'}</span>
                <span>AI: {aiPct}%</span>
              </div>
            </div>
          );
        })}
        {!loading && filtered.length === 0 ? (
          <div className="glassmorphism p-6 rounded border border-white/10 text-gray-300">
            No vulnerabilities match filters.
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <Shell
      title="Vulnerability Management"
      subtitle="Analyze and prioritize security findings"
      actions={
        <>
          <div className="flex items-center space-x-0">
            <button
              className={`view-toggle px-4 py-2 rounded-l text-sm ${viewMode === 'table' ? 'active' : ''}`}
              onClick={() => setViewMode('table')}
            >
              Table
            </button>
            <button
              className={`view-toggle px-4 py-2 rounded-r text-sm ${viewMode === 'cards' ? 'active' : ''}`}
              onClick={() => setViewMode('cards')}
            >
              Cards
            </button>
          </div>
          <button
            className="action-button px-4 py-2 rounded hover:bg-white/10 transition-all"
            onClick={exportCSV}
          >
            Export CSV
          </button>
        </>
      }
    >
      {error ? (
        <div className="glassmorphism p-4 rounded border border-white/10 text-sm text-gray-200 mb-6">
          {error}
        </div>
      ) : null}

      <div className="mb-6 border-b border-white/10 pb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <input
                type="text"
                placeholder="Search vulnerabilities..."
                className="search-input w-64 px-4 py-2 rounded-lg placeholder-gray-400"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              <span className="absolute right-3 top-2.5 text-gray-400">&#x1F50D;</span>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">Sort by:</span>
            <select
              className="search-input px-3 py-2 rounded text-sm"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="severity" className="text-black">Severity</option>
              <option value="cvss" className="text-black">CVSS Score</option>
              <option value="status" className="text-black">Status</option>
              <option value="asset" className="text-black">Asset</option>
            </select>
          </div>
        </div>
      </div>

      <div className="flex gap-6">
        <div className="w-64 flex-shrink-0 filter-sidebar p-6 rounded-lg">
          <h3 className="text-lg font-semibold mb-6">Filters</h3>

          <div className="mb-6">
            <h4 className="text-sm font-medium mb-3 text-gray-300">Severity</h4>
            <div className="space-y-2">
              {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                <label key={s} className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    className="filter-checkbox"
                    checked={severityFilter[s] || false}
                    onChange={() => setSeverityFilter((prev) => ({ ...prev, [s]: !prev[s] }))}
                  />
                  <span className={`${severityBadge(s)} px-2 py-1 rounded text-xs`}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </span>
                  <span className="text-xs text-gray-400">({counts.sev[s] || 0})</span>
                </label>
              ))}
            </div>
          </div>

          <div className="mb-6">
            <h4 className="text-sm font-medium mb-3 text-gray-300">Status</h4>
            <div className="space-y-2">
              {[
                { key: 'open', label: 'Open' },
                { key: 'in-progress', label: 'In Progress' },
                { key: 'closed', label: 'Closed' },
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    className="filter-checkbox"
                    checked={statusFilter[key]}
                    onChange={() => setStatusFilter((prev) => ({ ...prev, [key]: !prev[key] }))}
                  />
                  <span className="text-sm">{label}</span>
                  <span className="text-xs text-gray-400">({counts.st[key]})</span>
                </label>
              ))}
            </div>
          </div>

          <div className="mb-6">
            <h4 className="text-sm font-medium mb-3 text-gray-300">Assets</h4>
            <div className="space-y-2">
              {Object.entries(counts.assets)
                .slice(0, 5)
                .map(([asset, count]) => (
                  <div key={asset} className="flex items-center justify-between text-sm">
                    <span className="text-gray-300 truncate max-w-[150px]">{asset}</span>
                    <span className="text-xs text-gray-400">({count})</span>
                  </div>
                ))}
            </div>
          </div>

          <button
            className="w-full action-button px-4 py-2 rounded text-sm"
            onClick={clearFilters}
          >
            Clear All Filters
          </button>
        </div>

        <div className="flex-1">
          <div className="bulk-actions p-4 rounded-lg mb-6 flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="filter-checkbox"
                  checked={allSelected}
                  onChange={toggleSelectAll}
                />
                <span className="text-sm">Select All</span>
              </label>
              <span className="text-sm text-gray-400">|</span>
              <span className="text-sm text-gray-400">
                {loading ? 'Loading...' : `${filtered.length} vulnerabilities found`}
                {selectedIds.size > 0 && ` (${selectedIds.size} selected)`}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                className="action-button px-3 py-1 rounded text-sm"
                disabled={selectedIds.size === 0}
                onClick={() => setShowStatusPicker(true)}
              >
                Update Status ({selectedIds.size})
              </button>
              <button
                className="action-button px-3 py-1 rounded text-sm"
                onClick={exportCSV}
              >
                Export {selectedIds.size > 0 ? `Selected (${selectedIds.size})` : 'All'}
              </button>
            </div>
          </div>

          {viewMode === 'table' ? renderTable() : renderCards()}
        </div>
      </div>

      <VulnDetailModal
        open={!!selectedVuln}
        vuln={selectedVuln}
        onClose={() => setSelectedVuln(null)}
        onStatusChange={handleVulnStatusChange}
      />

      <StatusPickerModal
        open={showStatusPicker}
        vulnIds={selectedIds}
        onClose={() => setShowStatusPicker(false)}
        onDone={handleBulkStatusDone}
      />
    </Shell>
  );
}
