import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { apiFetch } from '../lib/api.js';

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'active') return 'status-active';
  if (s === 'completed') return 'status-completed';
  return 'status-planned';
}

function scanStatusColor(status) {
  const s = (status || '').toLowerCase();
  if (s === 'running') return 'text-white bg-white/20 animate-pulse';
  if (s === 'completed') return 'text-green-400 bg-green-500/20';
  if (s === 'failed') return 'text-red-400 bg-red-500/20';
  return 'text-gray-400 bg-white/10';
}

export default function ProjectDetailModal({ open, project, onClose }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open || !project?.id) return;
    setLoading(true);
    apiFetch(`/api/projects/${project.id}`)
      .then((d) => setScans(d?.scans || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [open, project?.id]);

  if (!open || !project) return null;

  const status = (project.status || 'active').toLowerCase();

  function handleScanClick(scan, e) {
    e.stopPropagation();
    onClose();
    // Navigate to vulnerabilities page with scan filter
    navigate(`/vulnerabilities?scanId=${scan.id}&target=${encodeURIComponent(scan.target || '')}`);
  }

  function handleViewAllVulns(e) {
    e.stopPropagation();
    onClose();
    // Navigate to vulnerabilities filtered by project
    navigate(`/vulnerabilities?projectId=${project.id}`);
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" 
          onClick={onClose}
        >
          <motion.div 
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            className="modal-content w-full max-w-3xl mx-4 rounded-2xl p-6 max-h-[90vh] overflow-y-auto" 
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                <span className={`${statusBadge(status)} px-3 py-1 rounded-full text-xs font-medium`}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </span>
                <h3 className="text-2xl font-bold">{project.name || 'Project Detail'}</h3>
              </div>
              <motion.button 
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                className="text-gray-400 hover:text-white text-xl p-2 hover:bg-white/10 rounded-lg transition-colors" 
                onClick={onClose}
              >
                ✕
              </motion.button>
            </div>

            <div className="space-y-6">
              {/* Overview */}
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="grid grid-cols-2 md:grid-cols-4 gap-4"
              >
                <div className="p-3 bg-white/5 rounded-xl">
                  <p className="text-xs text-gray-400">Client</p>
                  <p className="font-medium text-sm">{project.client || '\u2014'}</p>
                </div>
                <div className="p-3 bg-white/5 rounded-xl">
                  <p className="text-xs text-gray-400">Owner</p>
                  <p className="font-medium text-sm">{project.owner || '\u2014'}</p>
                </div>
                <div className="p-3 bg-white/5 rounded-xl">
                  <p className="text-xs text-gray-400">Scans</p>
                  <p className="font-medium text-sm">{project.scanCount ?? 0}</p>
                </div>
                <motion.div 
                  whileHover={{ scale: 1.02 }}
                  className="p-3 bg-white/5 rounded-xl cursor-pointer hover:bg-white/10 transition-colors"
                  onClick={handleViewAllVulns}
                >
                  <p className="text-xs text-gray-400">Vulnerabilities</p>
                  <p className="font-medium text-sm flex items-center gap-2">
                    {project.vulnerabilityCount ?? 0}
                    <span className="text-xs text-blue-400">View all →</span>
                  </p>
                </motion.div>
              </motion.div>

              {/* Description */}
              {project.description && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.15 }}
                >
                  <h4 className="text-sm font-medium text-gray-300 mb-2">Description</h4>
                  <div className="p-4 bg-white/5 rounded-xl text-sm text-gray-200">{project.description}</div>
                </motion.div>
              )}

              {/* Scope */}
              {project.scope && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                >
                  <h4 className="text-sm font-medium text-gray-300 mb-2">Scope</h4>
                  <div className="p-4 bg-white/5 rounded-xl text-sm text-gray-200 font-mono">{project.scope}</div>
                </motion.div>
              )}

              {/* Duration */}
              {(project.startDate || project.endDate) && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.25 }}
                  className="flex items-center space-x-4 text-sm text-gray-300"
                >
                  <span>Start: {project.startDate || '\u2014'}</span>
                  <span>End: {project.endDate || '\u2014'}</span>
                </motion.div>
              )}

              {/* Associated Scans */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <h4 className="text-sm font-medium text-gray-300 mb-3">Associated Scans</h4>
                {loading ? (
                  <div className="text-sm text-gray-400 flex items-center gap-2">
                    <motion.span
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                      className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full inline-block"
                    />
                    Loading scans...
                  </div>
                ) : scans.length === 0 ? (
                  <div className="text-sm text-gray-400 p-4 bg-white/5 rounded-xl">No scans attached to this project.</div>
                ) : (
                  <div className="space-y-3">
                    {scans.map((s, index) => (
                      <motion.div 
                        key={s.id} 
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.05 }}
                        whileHover={{ scale: 1.01, x: 4 }}
                        whileTap={{ scale: 0.99 }}
                        className="p-4 bg-white/5 rounded-xl flex items-center justify-between cursor-pointer hover:bg-white/10 transition-all border border-transparent hover:border-white/20 group"
                        onClick={(e) => handleScanClick(s, e)}
                      >
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <p className="text-sm font-medium text-blue-400 group-hover:text-blue-300 transition-colors">
                              🔗 {s.target || 'Unknown'}
                            </p>
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${scanStatusColor(s.status)}`}>
                              {(s.status || 'unknown').toUpperCase()}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 flex items-center gap-2">
                            <span>{s.template || 'scan'}</span>
                            <span>•</span>
                            <span className={s.vulnerabilitiesFound > 0 ? 'text-yellow-400' : ''}>
                              {s.vulnerabilitiesFound ?? 0} findings
                            </span>
                          </p>
                        </div>
                        <div className="text-right flex items-center gap-3">
                          <div className="text-xs text-gray-400">
                            {s.startTime ? new Date(s.startTime).toLocaleDateString() : '\u2014'}
                          </div>
                          <motion.span 
                            initial={{ x: 0 }}
                            whileHover={{ x: 4 }}
                            className="text-gray-400 group-hover:text-white transition-colors"
                          >
                            →
                          </motion.span>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                )}
                
                {scans.length > 0 && (
                  <motion.p 
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.5 }}
                    className="text-xs text-gray-500 mt-3 text-center"
                  >
                    Click on a scan to view its vulnerabilities
                  </motion.p>
                )}
              </motion.div>
            </div>

            <div className="flex justify-end mt-6 gap-3">
              {project.vulnerabilityCount > 0 && (
                <motion.button 
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="px-6 py-3 glass-button rounded-xl"
                  onClick={handleViewAllVulns}
                >
                  View All Vulnerabilities
                </motion.button>
              )}
              <motion.button 
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="px-6 py-3 border border-white/30 rounded-xl hover:bg-white/10 transition-all" 
                onClick={onClose}
              >
                Close
              </motion.button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
