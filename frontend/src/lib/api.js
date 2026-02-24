const STORAGE = {
  token: 'vlolv_token',
  user: 'vlolv_user',
};

// Global callback set by AuthContext to handle 401 responses
let _onUnauthorized = null;
export function setOnUnauthorized(fn) {
  _onUnauthorized = fn;
}

export function getAuthToken() {
  return localStorage.getItem(STORAGE.token);
}

export function setAuth({ token, user }) {
  if (token) localStorage.setItem(STORAGE.token, token);
  if (user) localStorage.setItem(STORAGE.user, JSON.stringify(user));
}

export function clearStoredAuth() {
  localStorage.removeItem(STORAGE.token);
  localStorage.removeItem(STORAGE.user);
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem(STORAGE.user);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export async function apiFetch(path, options = {}) {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (!headers.has('Content-Type') && options.body && typeof options.body !== 'string') {
    headers.set('Content-Type', 'application/json');
  }
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const body = options.body && typeof options.body !== 'string' ? JSON.stringify(options.body) : options.body;
  const res = await fetch(path, { ...options, headers, body });
  const contentType = res.headers.get('content-type') || '';
  const payload = contentType.includes('application/json') ? await res.json().catch(() => ({})) : null;
  if (!res.ok) {
    if (res.status === 401 && _onUnauthorized) {
      _onUnauthorized();
    }
    const message = payload?.error || payload?.message || `Request failed: ${res.status}`;
    throw new Error(message);
  }
  return payload;
}

// ── Project helpers ─────────────────────────────────────────────────────────

export async function getProject(projectId) {
  return apiFetch(`/api/projects/${encodeURIComponent(projectId)}`);
}

export async function updateProject(projectId, data) {
  return apiFetch(`/api/projects/${encodeURIComponent(projectId)}`, {
    method: 'PUT',
    body: data,
  });
}

export async function deleteProject(projectId) {
  return apiFetch(`/api/projects/${encodeURIComponent(projectId)}`, {
    method: 'DELETE',
  });
}

// ── Vulnerability helpers ───────────────────────────────────────────────────

export async function updateVulnStatus(vulnId, status) {
  return apiFetch(`/api/scan/results/${encodeURIComponent(vulnId)}/status`, {
    method: 'PUT',
    body: { status },
  });
}

// ── Report helpers ──────────────────────────────────────────────────────────

export async function downloadPdfReport(type, id) {
  const token = getAuthToken();
  const params = new URLSearchParams({ type });
  if (id) params.set('id', id);

  const res = await fetch(`/api/reports/generate?${params.toString()}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      const data = await res.json();
      throw new Error(data.error || 'Report generation failed');
    }
    throw new Error(`Report generation failed: ${res.status}`);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `security-report-${type}-${new Date().toISOString().slice(0, 10)}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}
