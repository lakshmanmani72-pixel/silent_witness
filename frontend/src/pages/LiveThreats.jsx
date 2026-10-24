import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Radio,
  Search,
  Filter,
  Download,
  Eye,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Wifi,
  ExternalLink,
  Info,
  Clock,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { endpoints } from '../services/api';

const LiveThreats = () => {
  const navigate = useNavigate();

  // Threat list & pagination state
  const [threats, setThreats] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);

  // Filter controls
  const [searchIP, setSearchIP] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [timeRange, setTimeRange] = useState('24h');
  const [sortBy, setSortBy] = useState('timestamp_desc');

  // WebSocket state
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  // Slide-out detailed investigation panel
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [investigationData, setInvestigationData] = useState(null);

  // Fetch threats from API
  const fetchThreats = async () => {
    try {
      setLoading(true);
      const params = {
        page,
        page_size: pageSize,
        src_ip: searchIP || undefined,
        severity: severityFilter || undefined,
        threat_type: typeFilter || undefined,
        time_range: timeRange || undefined,
        sort: sortBy,
      };
      const res = await endpoints.getThreats(params);
      setThreats(res.data.threats || []);
      setTotal(res.data.total || 0);
      setPages(res.data.pages || 1);
    } catch (err) {
      console.error('Failed to load threats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [page, severityFilter, typeFilter, timeRange, sortBy]);

  // Handle Search submission
  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchThreats();
  };

  // WebSocket Real-Time Connection
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;

    let reconnectTimer = null;

    let isSubscribed = true;

    const connectWs = () => {
      if (!isSubscribed) return;
      try {
        const socket = new WebSocket(wsUrl);
        wsRef.current = socket;

        socket.onopen = () => {
          if (isSubscribed) setWsConnected(true);
        };

        socket.onmessage = (event) => {
          if (!isSubscribed) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'threat') {
              fetchThreats();
            }
          } catch (e) {
            // heartbeat
          }
        };

        socket.onclose = () => {
          if (isSubscribed) {
            setWsConnected(false);
            reconnectTimer = setTimeout(connectWs, 4000);
          }
        };

        socket.onerror = () => {
          try { socket.close(); } catch {}
        };
      } catch (err) {
        if (isSubscribed) {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectWs, 4000);
        }
      }
    };

    connectWs();

    // Fallback polling
    const pollingInterval = setInterval(() => {
      fetchThreats();
    }, 5000);

    return () => {
      isSubscribed = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearInterval(pollingInterval);
      if (wsRef.current) {
        try { wsRef.current.close(); } catch {}
      }
    };
  }, []); // Run ONCE on mount

  // Load detailed threat info when clicked
  const handleInspectThreat = async (threat) => {
    setSelectedThreat(threat);
    try {
      const res = await endpoints.getThreatDetails(threat.id);
      setInvestigationData(res.data);
    } catch {
      setInvestigationData(threat);
    }
  };

  const getDefensiveRecommendation = (threatType, severity) => {
    if (threatType === 'SYN_FLOOD') {
      return 'Rate-limit half-open TCP connections, enable syncookies on host, and temporary drop rule via firewall response engine.';
    }
    if (threatType === 'PORT_SCAN') {
      return 'Inspect source IP reconnaissance frequency, verify firewall drop rules on unmapped listening ports, and add source to watch-list.';
    }
    return 'Monitor source IP traffic patterns for repeated anomalies.';
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono-code flex items-center gap-2">
              <Radio className="w-5 h-5 text-cyber-cyan animate-pulse" />
              Live Threat Monitor
            </h1>
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono-code font-bold uppercase flex items-center gap-1 ${
              wsConnected
                ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30'
                : 'bg-cyber-amber/10 text-cyber-amber border border-cyber-amber/30'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-cyber-green animate-ping' : 'bg-cyber-amber'}`} />
              {wsConnected ? 'WebSocket Live Feed' : 'HTTP Polling (5s)'}
            </span>
          </div>
          <p className="text-xs text-cyber-muted mt-1">
            Real-time defensive triage, rolling window detection, and packet metadata inspection.
          </p>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          <a
            href={endpoints.getThreatsCsvUrl({
              src_ip: searchIP || undefined,
              severity: severityFilter || undefined,
              threat_type: typeFilter || undefined,
              time_range: timeRange || undefined,
            })}
            download
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-card border border-cyber-border/40 hover:border-cyber-cyan text-xs font-mono-code text-cyber-text hover:text-cyber-cyan transition-all shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Filtered CSV</span>
          </a>

          <button
            onClick={fetchThreats}
            className="p-2 rounded-lg bg-cyber-card border border-cyber-border/40 hover:bg-cyber-panel text-cyber-muted hover:text-cyber-cyan transition-colors"
            title="Refresh Table"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 shadow-lg flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs font-mono-code">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search by Source IP (e.g. 10.0.0.99)..."
            value={searchIP}
            onChange={(e) => setSearchIP(e.target.value)}
            className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg pl-9 pr-4 py-2 text-cyber-text placeholder:text-cyber-muted/60 focus:outline-none focus:border-cyber-cyan"
          />
        </form>

        {/* Filter dropdowns */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Threat Type */}
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Threat Types</option>
            <option value="SYN_FLOOD">SYN Flood</option>
            <option value="PORT_SCAN">Port Scan</option>
            <option value="SUSPICIOUS">Suspicious Activity</option>
          </select>

          {/* Severity */}
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Time Range */}
          <select
            value={timeRange}
            onChange={(e) => { setTimeRange(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>

          {/* Sort */}
          <select
            value={sortBy}
            onChange={(e) => { setSortBy(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="timestamp_desc">Newest First</option>
            <option value="timestamp_asc">Oldest First</option>
            <option value="severity_desc">Highest Severity</option>
          </select>
        </div>
      </div>

      {/* Main Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono-code border-collapse">
            <thead>
              <tr className="border-b border-cyber-border/40 text-cyber-muted uppercase text-[11px] tracking-wider bg-cyber-panel/50">
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Source IP</th>
                <th className="py-3 px-4 font-semibold">Destination IP</th>
                <th className="py-3 px-4 font-semibold">Src Port</th>
                <th className="py-3 px-4 font-semibold">Dst Port</th>
                <th className="py-3 px-4 font-semibold">Protocol</th>
                <th className="py-3 px-4 font-semibold">Threat Vector</th>
                <th className="py-3 px-4 font-semibold">Count</th>
                <th className="py-3 px-4 font-semibold">Severity</th>
                <th className="py-3 px-4 font-semibold">Response</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {threats.length === 0 ? (
                <tr>
                  <td colSpan="11" className="py-12 text-center text-cyber-muted">
                    No threat events found matching current filters.
                  </td>
                </tr>
              ) : (
                threats.map((t) => {
                  const isBlocked = t.response_status && t.response_status.includes('blocked');
                  return (
                    <tr
                      key={t.id}
                      className="hover:bg-cyber-panel/50 transition-colors group"
                    >
                      <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                        {new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="font-bold text-cyber-cyan">{t.src_ip}</span>
                      </td>
                      <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                        {t.dst_ip || '--'}
                      </td>
                      <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                        {t.src_port || '--'}
                      </td>
                      <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                        {t.dst_port || '--'}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-text">
                          {t.protocol || 'TCP'}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-semibold text-white whitespace-nowrap">
                        {t.threat_type}
                      </td>
                      <td className="py-3 px-4 font-bold text-cyber-text whitespace-nowrap">
                        {t.count}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <SeverityBadge severity={t.severity} />
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          isBlocked
                            ? 'bg-red-500/10 text-cyber-red border border-cyber-red/30'
                            : 'bg-cyber-panel text-cyber-muted border border-cyber-border/30'
                        }`}>
                          {t.response_status || 'monitored'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap space-x-1">
                        <button
                          onClick={() => handleInspectThreat(t)}
                          className="px-2.5 py-1 rounded bg-cyber-panel hover:bg-cyber-cyan hover:text-black border border-cyber-border/40 text-cyber-text transition-all"
                        >
                          Details
                        </button>
                        <button
                          onClick={() => navigate(`/intelligence?ip=${t.src_ip}`)}
                          className="px-2.5 py-1 rounded bg-cyber-panel hover:bg-cyber-blue hover:text-white border border-cyber-border/40 text-cyber-muted transition-all"
                          title="Investigate IP History"
                        >
                          Intel
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination footer */}
        <div className="p-4 border-t border-cyber-border/30 flex items-center justify-between text-xs font-mono-code text-cyber-muted">
          <div>
            Showing {threats.length} of {total} records (Page {page} of {pages})
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded bg-cyber-panel border border-cyber-border/40 disabled:opacity-30 hover:border-cyber-cyan transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 font-bold text-cyber-cyan">{page}</span>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages}
              className="p-1.5 rounded bg-cyber-panel border border-cyber-border/40 disabled:opacity-30 hover:border-cyber-cyan transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* ── Slide-Out Detailed Investigation Panel ───────────────────────────── */}
      {selectedThreat && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-cyber-secondary border-l border-cyber-border shadow-2xl z-50 p-6 overflow-y-auto animate-slideIn">
          <div className="flex items-center justify-between pb-4 border-b border-cyber-border/40">
            <div>
              <h2 className="text-base font-bold text-cyber-text font-mono-code flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyber-red" />
                Security Incident #{selectedThreat.id}
              </h2>
              <p className="text-xs text-cyber-muted font-mono-code">
                Detection Timestamp: {new Date(selectedThreat.timestamp).toUTCString()}
              </p>
            </div>
            <button
              onClick={() => setSelectedThreat(null)}
              className="p-1 text-cyber-muted hover:text-white text-lg font-bold"
            >
              &times;
            </button>
          </div>

          <div className="mt-5 space-y-4 font-mono-code text-xs">
            {/* Packet Metadata Grid */}
            <div className="bg-cyber-card border border-cyber-border/40 rounded-xl p-4 space-y-2">
              <h3 className="text-xs uppercase font-bold text-cyber-cyan tracking-wider">
                Packet Metadata & Vector
              </h3>
              <div className="grid grid-cols-2 gap-3 pt-2">
                <div>
                  <span className="text-cyber-muted">Source IP:</span>
                  <p className="text-cyber-cyan font-bold text-sm">{selectedThreat.src_ip}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Destination IP:</span>
                  <p className="text-cyber-text font-bold text-sm">{selectedThreat.dst_ip || 'Local Gateway'}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Port Mapping:</span>
                  <p className="text-cyber-text">
                    Src: {selectedThreat.src_port || 'ephemeral'} &rarr; Dst: {selectedThreat.dst_port || 'multiple'}
                  </p>
                </div>
                <div>
                  <span className="text-cyber-muted">Protocol:</span>
                  <p className="text-cyber-text font-bold">{selectedThreat.protocol || 'TCP'}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Detected Severity:</span>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedThreat.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-cyber-muted">Event Source:</span>
                  <p className="mt-1">
                    <span className="px-2 py-0.5 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-cyan uppercase font-bold text-[10px]">
                      {selectedThreat.event_source === 'simulation' ? 'DEMO SIMULATION' : 'LIVE NETWORK'}
                    </span>
                  </p>
                </div>
              </div>
            </div>

            {/* Detection Rule Explanation */}
            <div className="bg-cyber-card border border-cyber-border/40 rounded-xl p-4 space-y-1.5">
              <h3 className="text-xs uppercase font-bold text-cyber-amber tracking-wider">
                Triggered Rule & Threshold
              </h3>
              <p className="text-cyber-text leading-relaxed font-sans pt-1">
                {selectedThreat.detection_reason || 'Detection threshold exceeded within rolling window.'}
              </p>
            </div>

            {/* Recommended Defensive Action */}
            <div className="bg-cyber-card border border-cyber-border/40 rounded-xl p-4 space-y-1.5">
              <h3 className="text-xs uppercase font-bold text-cyber-green tracking-wider">
                Recommended Defensive Response
              </h3>
              <p className="text-cyber-text leading-relaxed font-sans pt-1">
                {getDefensiveRecommendation(selectedThreat.threat_type, selectedThreat.severity)}
              </p>
            </div>

            {/* Privacy Guarantee Note */}
            <div className="p-3 bg-cyber-panel border border-cyber-border/30 rounded-lg text-cyber-muted text-[11px] font-sans flex items-start gap-2">
              <Info className="w-4 h-4 text-cyber-cyan shrink-0 mt-0.5" />
              <span>
                <strong>Privacy Safeguard:</strong> SILENT WITNESS operates exclusively on passive header metadata. Raw network packet payloads are never inspected, buffered, or stored.
              </span>
            </div>

            {/* Related incidents */}
            {investigationData?.related_incidents?.length > 0 && (
              <div className="bg-cyber-card border border-cyber-border/40 rounded-xl p-4 space-y-2">
                <h3 className="text-xs uppercase font-bold text-cyber-text tracking-wider">
                  Linked Incident Audits ({investigationData.related_incidents.length})
                </h3>
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {investigationData.related_incidents.map((inc) => (
                    <div key={inc.id} className="p-2 rounded bg-cyber-panel border border-cyber-border/20 flex items-center justify-between">
                      <span>Incident #{inc.id} - {inc.incident_type}</span>
                      <span className="text-cyber-cyan">{inc.action_status}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer Buttons */}
            <div className="pt-4 flex items-center justify-between border-t border-cyber-border/30">
              <button
                onClick={() => navigate(`/intelligence?ip=${selectedThreat.src_ip}`)}
                className="px-4 py-2 rounded-lg bg-cyber-cyan hover:bg-cyan-400 text-black font-bold flex items-center gap-1.5 shadow-cyan-glow transition-all"
              >
                <span>Investigate IP Profile</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-2 rounded-lg bg-cyber-card border border-cyber-border/40 text-cyber-muted hover:text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveThreats;
