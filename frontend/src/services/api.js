/**
 * OrgShield AI - Centralized API Communication Service
 * Manages all HTTP/REST interactions between React frontend and FastAPI backend.
 * Supports configurable VITE_API_BASE_URL, Render cold-start timeout handling,
 * detailed health diagnostics, and local Vite development proxy.
 */

// Determine base backend URL
const envBase = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');

// Normalize known hostname variations (e.g. Render service slug is orgshield-ai)
let resolvedHost = envBase;
if (resolvedHost === 'https://org-shield-ai.onrender.com') {
  resolvedHost = 'https://orgshield-ai.onrender.com';
}

// In production, fallback to deployed Render backend if environment variable is omitted
const defaultProdHost = 'https://orgshield-ai.onrender.com';
const baseHost = resolvedHost || (import.meta.env.PROD ? defaultProdHost : '');

// API_BASE always points to the /api namespace without trailing slashes or duplicate paths
export const API_BASE = baseHost
  ? (baseHost.endsWith('/api') ? baseHost : `${baseHost}/api`)
  : '/api';

/**
 * Robust JSON fetch wrapper with AbortController timeout and structured error parsing.
 */
async function request(endpoint, options = {}, timeoutMs = 15000) {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const url = `${API_BASE}${cleanEndpoint}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    signal: controller.signal,
    ...options,
  };

  try {
    const res = await fetch(url, config);
    clearTimeout(timer);

    const contentType = res.headers.get('content-type') || '';

    if (!res.ok) {
      let message = `HTTP ${res.status}: ${res.statusText}`;
      if (contentType.includes('application/json')) {
        try {
          const errorJson = await res.json();
          if (errorJson && errorJson.detail) {
            message = typeof errorJson.detail === 'string'
              ? errorJson.detail
              : JSON.stringify(errorJson.detail);
          }
        } catch {
          // Fallback to HTTP status text
        }
      }
      const httpErr = new Error(message);
      httpErr.status = res.status;
      throw httpErr;
    }

    if (!contentType.includes('application/json')) {
      throw new Error(`API returned unexpected response format (${contentType || 'text/html'}). Ensure backend is reachable and healthy.`);
    }

    return await res.json();
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      const timeoutErr = new Error(`Request to ${cleanEndpoint} timed out after ${timeoutMs / 1000}s. The backend may be waking up from cold start.`);
      timeoutErr.isTimeout = true;
      throw timeoutErr;
    }
    throw err;
  }
}

/**
 * Comprehensive health status checker for UI connection badges.
 * Distinguishes:
 * - 'healthy': Connected, API is 200, ML models loaded
 * - 'unhealthy': API responded but returned unhealthy status or models not loaded
 * - 'timeout': Request timed out (Render free-tier cold start)
 * - 'offline': Network error or server unreachable
 */
export async function checkHealthDetailed(timeoutMs = 10000) {
  try {
    const data = await request('/health', {}, timeoutMs);
    if (data.status === 'healthy' && data.models_loaded) {
      return {
        state: 'healthy',
        label: 'ONLINE',
        message: 'Connected and healthy',
        active_model: data.active_model || 'one_class_svm',
        version: data.version || '1.0.0',
        data
      };
    }
    return {
      state: 'unhealthy',
      label: 'DEGRADED',
      message: data.status ? `Status: ${data.status}` : 'Backend reported degraded state',
      active_model: data.active_model || 'unknown',
      version: data.version || 'unknown',
      data
    };
  } catch (err) {
    if (err.isTimeout) {
      return {
        state: 'timeout',
        label: 'TIMEOUT',
        message: 'Backend waking up (cold start)... Please retry in a few seconds.',
        active_model: 'offline',
        version: 'unknown',
        error: err.message
      };
    }
    return {
      state: 'offline',
      label: 'OFFLINE',
      message: err.status ? `Backend Error ${err.status}` : 'Backend unavailable or network unreachable',
      active_model: 'offline',
      version: 'unknown',
      error: err.message
    };
  }
}

export const api = {
  // System Health
  getHealth: () => request('/health'),
  checkHealthDetailed,

  // Overview / Dashboard
  getDashboardSummary: () => request('/dashboard/summary'),
  getDatasetStats: () => request('/dataset/stats'),
  getModelsStatus: () => request('/models/status'),

  // Email Threat Discovery & Scanning
  scanEmail: (payload) => request('/emails/scan', {
    method: 'POST',
    body: JSON.stringify(payload)
  }, 25000), // Higher timeout for multi-feature inference

  bulkScanEmails: (payload) => request('/emails/bulk-scan', {
    method: 'POST',
    body: JSON.stringify(payload)
  }, 45000),

  // Threat Inbox & Alerts
  getAlerts: (params = {}) => {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset !== undefined) query.append('offset', params.offset);
    if (params.severity && params.severity !== 'ALL') query.append('severity', params.severity);
    if (params.threat_only) query.append('threat_only', 'true');
    if (params.query) query.append('query', params.query);
    const qs = query.toString();
    return request(`/alerts${qs ? `?${qs}` : ''}`);
  },

  getAlertDetail: (id) => request(`/alerts/${encodeURIComponent(id)}`),

  // Analytics & Forensics
  getAnalytics: () => request('/analytics'),

  // Model Evaluation Benchmark
  getEvaluation: () => request('/evaluation'),

  // Platform Settings & Sensitivity Calibration
  getSettings: () => request('/settings'),
  updateSettings: (payload) => request('/settings', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
};
