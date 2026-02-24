import { useState } from 'react';
import { apiFetch } from '../lib/api.js';

const STATUSES = [
  { value: 'open', label: 'Open' },
  { value: 'in-progress', label: 'In Progress' },
  { value: 'closed', label: 'Closed' },
];

export default function StatusPickerModal({ open, vulnIds, onClose, onDone }) {
  const [selected, setSelected] = useState('open');
  const [applying, setApplying] = useState(false);
  const [progress, setProgress] = useState(0);

  if (!open) return null;

  async function apply() {
    setApplying(true);
    setProgress(0);
    const ids = Array.from(vulnIds || []);
    let done = 0;
    for (const id of ids) {
      try {
        await apiFetch(`/api/scan/results/${id}/status`, {
          method: 'PUT',
          body: { status: selected },
        });
      } catch {
        // continue with others
      }
      done++;
      setProgress(Math.round((done / ids.length) * 100));
    }
    setApplying(false);
    onDone?.(selected);
    onClose();
  }

  return (
    <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" onClick={onClose}>
      <div className="modal-content w-full max-w-md mx-4 rounded-lg p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold">Update Status</h3>
          <button className="text-gray-400 hover:text-white text-xl" onClick={onClose}>&#x2715;</button>
        </div>

        <p className="text-sm text-gray-400 mb-4">
          Change status for {(vulnIds?.size || vulnIds?.length || 0)} selected vulnerabilities
        </p>

        <div className="space-y-3 mb-6">
          {STATUSES.map((s) => (
            <button
              key={s.value}
              className={`w-full text-left p-3 rounded-lg border transition-all ${
                selected === s.value ? 'border-white bg-white/10' : 'border-white/10 hover:border-white/30'
              }`}
              onClick={() => setSelected(s.value)}
            >
              <span className="font-medium text-sm">{s.label}</span>
            </button>
          ))}
        </div>

        {applying && (
          <div className="mb-4">
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div className="progress-bar h-2 rounded-full transition-all" style={{ width: `${progress}%` }} />
            </div>
            <p className="text-xs text-gray-400 mt-1">Updating... {progress}%</p>
          </div>
        )}

        <div className="flex justify-end space-x-4">
          <button
            className="px-6 py-3 border border-white/30 rounded hover:bg-white/10 transition-all"
            onClick={onClose}
            disabled={applying}
          >
            Cancel
          </button>
          <button
            className="px-6 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium disabled:opacity-50"
            onClick={apply}
            disabled={applying}
          >
            Apply
          </button>
        </div>
      </div>
    </div>
  );
}
