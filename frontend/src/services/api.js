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
  getFrequentThreats: (limit = 20) => api.get('/threats/frequent', { params: { limit } }),

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

  // Monitoring & Packets
  getMonitoringStatus: () => api.get('/monitoring/status'),
  getMonitoringInterfaces: () => api.get('/monitoring/interfaces'),
  startMonitoring: (iface) => api.post('/monitoring/start', { interface: iface }),
  stopMonitoring: () => api.post('/monitoring/stop'),
  startLiveMonitoring: (iface) => api.post('/monitoring/start', { interface: iface }),
  stopLiveMonitoring: () => api.post('/monitoring/stop'),
  getRecentPackets: (limit = 100) => api.get('/monitoring/recent-packets', { params: { limit } }),
  injectTraffic: (type, count = 20) => api.post('/monitoring/inject-traffic', { type, count }),
  toggleBlockingMode: (mode) => api.post('/monitoring/toggle-blocking-mode', { mode }),
  clearAllEvents: () => api.post('/monitoring/clear-all'),
  resetMonitoringState: () => api.post('/monitoring/clear-all'),

  // ML Service & Tree Explainability
  getMlStatus: () => api.get('/ml/status'),
  predictFlow: (features) => api.post('/ml/predict', { features }),
  explainFlow: (features, threatType) => api.post('/ml/explain', { features, threat_type: threatType }),
  getTreeExplanation: (threatType = 'SYN_FLOOD') =>
    api.get(`/ml/tree-explanation?threat_type=${threatType}`),

  // Manual Blocking & Unblocking
  manualBlockIp: (ip, reason = 'Manual block by operator', duration_min = 60) =>
    api.post('/blocked-ips/block', { ip, reason, duration_min }),
  manualBlockIP: (ip, reason = 'Manual block by operator', duration_min = 60) =>
    api.post('/blocked-ips/block', { ip, reason, duration_min }),
  unblockByIp: (ip) => api.post('/blocked-ips/unblock-by-ip', { ip }),
  manualUnblockIP: (ip) => api.post('/blocked-ips/unblock-by-ip', { ip }),

  // Simulation & Manual Attack Generation
  startSimulation: (speed = 1.0, scenario = 'mixed') => api.post('/simulation/start', { speed, scenario }),
  pauseSimulation: () => api.post('/simulation/pause'),
  resumeSimulation: () => api.post('/simulation/resume'),
  stopSimulation: () => api.post('/simulation/stop'),
  resetSimulation: () => api.post('/simulation/reset'),
  setSimulationScenario: (scenario) => api.post('/simulation/scenario', { scenario }),
  setSimulationSpeed: (speed) => api.post('/simulation/speed', { speed }),
  getSimulationStatus: () => api.get('/simulation/status'),
  generatePortScan: (target = '127.0.0.1', duration_sec = 10, port_range = '1-1024') =>
    api.post('/simulation/generate-port-scan', { target, duration_sec, port_range }),
  generateSynFlood: (target = '127.0.0.1', duration_sec = 10) =>
    api.post('/simulation/generate-syn-flood', { target, duration_sec }),
  stopGenerator: () => api.post('/simulation/stop-generator'),
  getGeneratorStatus: () => api.get('/simulation/generator-status'),

  // Explainer & Model Info
  getDetectionExplanation: (threatId = 'latest') => api.get(`/explain/${threatId}`),
  getRecentExplanations: (limit = 15) => api.get('/explain/recent', { params: { limit } }),
  getModelInfo: () => api.get('/model/info'),

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
