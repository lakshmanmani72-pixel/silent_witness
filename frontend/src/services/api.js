import axios from 'axios';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

export const endpoints = {
  // Health
  getHealth: () => api.get('/health'),

  // Dashboard
  getDashboardSummary: () => api.get('/dashboard/summary'),
  getTrafficStats: (range = '5m') => api.get(`/dashboard/traffic?range=${range}`),
  getSeverityDistribution: () => api.get('/dashboard/severity-distribution'),
  getThreatTypes: () => api.get('/dashboard/threat-types'),
  getRecentEvents: (limit = 10) => api.get(`/dashboard/recent-events?limit=${limit}`),
  getNetworkActivity: () => api.get('/dashboard/network-activity'),

  // Threats
  getThreats: (params = {}) => api.get('/threats', { params }),
  getThreatDetails: (id) => api.get(`/threats/${id}`),

  // Blocked IPs
  getBlockedIPs: (params = {}) => api.get('/blocked-ips', { params }),
  getBlockedIPDetails: (id) => api.get(`/blocked-ips/${id}`),
  unblockIP: (id, reason) => api.post(`/blocked-ips/${id}/unblock`, { reason }),

  // Incidents
  getIncidents: (params = {}) => api.get('/incidents', { params }),
  getIncidentDetails: (id) => api.get(`/incidents/${id}`),
  reviewIncident: (id, reviewed = true) => api.post(`/incidents/${id}/review`, { reviewed }),

  // Analytics
  getAnalyticsTraffic: (timeRange = '24h') => api.get(`/analytics/traffic?time_range=${timeRange}`),
  getAnalyticsThreats: (timeRange = '24h') => api.get(`/analytics/threats?time_range=${timeRange}`),
  getTopSources: (timeRange = '24h', limit = 10) => api.get(`/analytics/top-sources?time_range=${timeRange}&limit=${limit}`),
  getTopPorts: (timeRange = '24h', limit = 10) => api.get(`/analytics/top-ports?time_range=${timeRange}&limit=${limit}`),
  getProtocolDistribution: (timeRange = '24h') => api.get(`/analytics/protocol-distribution?time_range=${timeRange}`),
  getBlockedTrends: (timeRange = '24h') => api.get(`/analytics/blocked-trends?time_range=${timeRange}`),
  getIPIntelligence: (ip) => api.get(`/analytics/ip-intelligence/${ip}`),

  // Settings
  getSettings: () => api.get('/settings'),
  updateSettings: (data) => api.put('/settings', data),

  // Monitoring
  getMonitoringStatus: () => api.get('/monitoring/status'),
  getMonitoringInterfaces: () => api.get('/monitoring/interfaces'),
  startMonitoring: (iface) => api.post('/monitoring/start', { interface: iface }),
  stopMonitoring: () => api.post('/monitoring/stop'),

  // Simulation
  startSimulation: (speed = 1.0) => api.post('/simulation/start', { speed }),
  pauseSimulation: () => api.post('/simulation/pause'),
  resumeSimulation: () => api.post('/simulation/resume'),
  stopSimulation: () => api.post('/simulation/stop'),
  resetSimulation: () => api.post('/simulation/reset'),
  getSimulationStatus: () => api.get('/simulation/status'),

  // Reports
  getReportSummary: (timeRange = '24h') => api.get(`/reports/summary?time_range=${timeRange}`),
  getThreatsCsvUrl: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return `/api/reports/threats.csv${q ? '?' + q : ''}`;
  },
  getIncidentsCsvUrl: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return `/api/reports/incidents.csv${q ? '?' + q : ''}`;
  },
};

export default api;
