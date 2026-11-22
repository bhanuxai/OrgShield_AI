/**
 * OrgShield AI - API Communication Service
 * Supports configurable VITE_API_BASE_URL for production deployments (e.g. Vercel -> Render)
 * with graceful fallback to relative /api for local Vite proxy.
 */

const rawBase = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');
const API_BASE = rawBase ? (rawBase.endsWith('/api') ? rawBase : `${rawBase}/api`) : '/api';

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  };

  try {
    const res = await fetch(url, config);
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `HTTP Error ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    console.error(`API Error [${endpoint}]:`, err);
    throw err;
  }
}

export const api = {
  getHealth: () => request('/health'),
  getDashboardSummary: () => request('/dashboard/summary'),
  getDatasetStats: () => request('/dataset/stats'),
  getModelsStatus: () => request('/models/status'),
  scanEmail: (payload) => request('/emails/scan', { method: 'POST', body: JSON.stringify(payload) }),
  bulkScanEmails: (payload) => request('/emails/bulk-scan', { method: 'POST', body: JSON.stringify(payload) }),
  getAlerts: (params = {}) => {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset !== undefined) query.append('offset', params.offset);
    if (params.severity) query.append('severity', params.severity);
    if (params.threat_only) query.append('threat_only', 'true');
    if (params.query) query.append('query', params.query);
    const qs = query.toString();
    return request(`/alerts${qs ? `?${qs}` : ''}`);
  },
  getAlertDetail: (id) => request(`/alerts/${id}`),
  getAnalytics: () => request('/analytics'),
  getEvaluation: () => request('/evaluation'),
  getSettings: () => request('/settings'),
  updateSettings: (payload) => request('/settings', { method: 'POST', body: JSON.stringify(payload) }),
};
