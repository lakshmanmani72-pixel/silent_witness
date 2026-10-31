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
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-ink font-mono-code flex items-center gap-2">
              <Radio className="w-5 h-5 text-forest animate-pulse" />
              Live Threat Monitor
            </h1>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono-code font-bold uppercase flex items-center gap-1.5 ${
              wsConnected
                ? 'bg-good/15 text-good-ink border border-good/30'
                : 'bg-amber/15 text-amber-ink border border-amber/30'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-good animate-ping' : 'bg-amber'}`} />
              {wsConnected ? 'WebSocket Live Feed' : 'HTTP Polling (5s)'}
            </span>
          </div>
          <p className="text-xs text-muted mt-1">
            Real-time defensive triage, rolling window detection, and packet metadata inspection stream.
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
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sage border border-bluegrey/40 hover:border-bluegrey text-xs font-mono-code text-ink transition-all shadow-neumorph-sm"
          >
            <Download className="w-3.5 h-3.5 text-forest" />
            <span>Export Filtered CSV</span>
          </a>

          <button
            onClick={fetchThreats}
            className="p-2 rounded-lg bg-sage border border-bluegrey/40 hover:bg-surface text-muted hover:text-ink transition-colors shadow-neumorph-sm"
            title="Refresh Table"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-forest' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs font-mono-code">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search by Source IP (e.g. 10.0.0.99)..."
            value={searchIP}
            onChange={(e) => setSearchIP(e.target.value)}
            className="w-full bg-surface border border-bluegrey/40 rounded-lg pl-9 pr-4 py-2 text-ink placeholder:text-muted/50 focus:outline-none focus:border-bluegrey shadow-neumorph-inset"
          />
        </form>

        {/* Filter dropdowns */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Threat Type */}
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="bg-surface border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey shadow-neumorph-inset"
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
            className="bg-surface border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey shadow-neumorph-inset"
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
            className="bg-surface border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey shadow-neumorph-inset"
          >
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>

          {/* Sort */}
          <select
            value={sortBy}
            onChange={(e) => { setSortBy(e.target.value); setPage(1); }}
            className="bg-surface border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey shadow-neumorph-inset"
          >
            <option value="timestamp_desc">Newest First</option>
            <option value="timestamp_asc">Oldest First</option>
            <option value="severity_desc">Highest Severity</option>
          </select>
        </div>
      </div>

      {/* Main Table */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl shadow-soft overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono-code border-collapse">
            <thead>
              <tr className="border-b border-bluegrey/40 text-muted uppercase text-[11px] tracking-wider bg-sage/80">
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
            <tbody className="divide-y divide-bluegrey/30">
              {threats.length === 0 ? (
                <tr>
                  <td colSpan="11" className="py-12 text-center text-muted">
                    No threat events found matching current filters.
                  </td>
                </tr>
              ) : (
                threats.map((t) => {
                  const isBlocked = t.response_status && t.response_status.includes('blocked');
                  return (
                    <tr
                      key={t.id}
                      className="hover:bg-sage/60 transition-colors group"
                    >
                      <td className="py-3 px-4 text-muted whitespace-nowrap">
                        {new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="font-bold text-forest">{t.src_ip}</span>
                      </td>
                      <td className="py-3 px-4 text-muted whitespace-nowrap">
                        {t.dst_ip || '--'}
                      </td>
                      <td className="py-3 px-4 text-muted whitespace-nowrap">
                        {t.src_port || '--'}
                      </td>
                      <td className="py-3 px-4 text-muted whitespace-nowrap">
                        {t.dst_port || '--'}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-sage border border-bluegrey/50 text-ink">
                          {t.protocol || 'TCP'}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-semibold text-ink whitespace-nowrap">
                        {t.threat_type}
                      </td>
                      <td className="py-3 px-4 font-bold text-ink whitespace-nowrap">
                        {t.count}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <SeverityBadge severity={t.severity} />
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          isBlocked
                            ? 'bg-bad/15 text-bad-ink border border-bad/30'
                            : 'bg-sage text-muted border border-bluegrey/40'
                        }`}>
                          {t.response_status || 'monitored'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap space-x-1.5">
                        <button
                          onClick={() => handleInspectThreat(t)}
                          className="px-2.5 py-1 rounded-lg bg-sage hover:bg-forest hover:text-white border border-bluegrey/40 text-ink text-xs transition-all shadow-neumorph-sm"
                        >
                          Details
                        </button>
                        <button
                          onClick={() => navigate(`/intelligence?ip=${t.src_ip}`)}
                          className="px-2.5 py-1 rounded-lg bg-sage hover:bg-forest hover:text-surface border border-bluegrey/50 text-muted text-xs transition-all shadow-neumorph-sm"
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
        <div className="p-4 border-t border-bluegrey/40 flex items-center justify-between text-xs font-mono-code text-muted bg-sage/50">
          <div>
            Showing {threats.length} of {total} records (Page {page} of {pages})
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg bg-sage border border-bluegrey/40 disabled:opacity-30 hover:border-bluegrey text-ink transition-colors shadow-neumorph-sm"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 font-bold text-forest">{page}</span>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages}
              className="p-1.5 rounded-lg bg-sage border border-bluegrey/40 disabled:opacity-30 hover:border-bluegrey text-ink transition-colors shadow-neumorph-sm"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* ── Slide-Out Detailed Investigation Panel ───────────────────────────── */}
      {selectedThreat && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-surface border-l border-bluegrey/40 shadow-soft z-50 p-6 overflow-y-auto animate-slideIn">
          <div className="flex items-center justify-between pb-4 border-b border-bluegrey/25">
            <div>
              <h2 className="text-base font-bold text-ink font-mono-code flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-bad-ink" />
                Security Incident #{selectedThreat.id}
              </h2>
              <p className="text-xs text-muted font-mono-code mt-0.5">
                Detection Timestamp: {new Date(selectedThreat.timestamp).toUTCString()}
              </p>
            </div>
            <button
              onClick={() => setSelectedThreat(null)}
              className="p-1 text-muted hover:text-ink text-xl font-bold rounded-lg hover:bg-sage"
            >
              &times;
            </button>
          </div>

          <div className="mt-5 space-y-4 font-mono-code text-xs">
            {/* Packet Metadata Grid */}
            <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 space-y-2 shadow-soft">
              <h3 className="text-xs uppercase font-bold text-forest tracking-wider">
                Packet Metadata & Vector
              </h3>
              <div className="grid grid-cols-2 gap-3 pt-2">
                <div>
                  <span className="text-muted">Source IP:</span>
                  <p className="text-forest font-bold text-sm mt-0.5">{selectedThreat.src_ip}</p>
                </div>
                <div>
                  <span className="text-muted">Destination IP:</span>
                  <p className="text-ink font-bold text-sm mt-0.5">{selectedThreat.dst_ip || 'Local Gateway'}</p>
                </div>
                <div>
                  <span className="text-muted">Port Mapping:</span>
                  <p className="text-ink mt-0.5">
                    Src: {selectedThreat.src_port || 'ephemeral'} &rarr; Dst: {selectedThreat.dst_port || 'multiple'}
                  </p>
                </div>
                <div>
                  <span className="text-muted">Protocol:</span>
                  <p className="text-ink font-bold mt-0.5">{selectedThreat.protocol || 'TCP'}</p>
                </div>
                <div>
                  <span className="text-muted">Detected Severity:</span>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedThreat.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-muted">Event Source:</span>
                  <p className="mt-1">
                    <span className="px-2 py-0.5 rounded bg-sage border border-bluegrey/50 text-forest uppercase font-bold text-[10px]">
                      {selectedThreat.event_source === 'simulation' ? 'DEMO SIMULATION' : 'LIVE NETWORK'}
                    </span>
                  </p>
                </div>
              </div>
            </div>

            {/* Detection Rule Explanation */}
            <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 space-y-1.5 shadow-soft">
              <h3 className="text-xs uppercase font-bold text-amber-ink tracking-wider">
                Triggered Rule & Threshold
              </h3>
              <p className="text-ink leading-relaxed font-sans pt-1">
                {selectedThreat.detection_reason || 'Detection threshold exceeded within rolling window.'}
              </p>
            </div>

            {/* Recommended Defensive Action */}
            <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 space-y-1.5 shadow-soft">
              <h3 className="text-xs uppercase font-bold text-good-ink tracking-wider">
                Recommended Defensive Response
              </h3>
              <p className="text-ink leading-relaxed font-sans pt-1">
                {getDefensiveRecommendation(selectedThreat.threat_type, selectedThreat.severity)}
              </p>
            </div>

            {/* Privacy Guarantee Note */}
            <div className="p-3 bg-sage border border-bluegrey/50 rounded-lg text-muted text-[11px] font-sans flex items-start gap-2">
              <Info className="w-4 h-4 text-forest shrink-0 mt-0.5" />
              <span>
                <strong>Privacy Safeguard:</strong> SILENT WITNESS operates exclusively on passive header metadata. Raw network packet payloads are never inspected, buffered, or stored.
              </span>
            </div>

            {/* Related incidents */}
            {investigationData?.related_incidents?.length > 0 && (
              <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 space-y-2 shadow-soft">
                <h3 className="text-xs uppercase font-bold text-ink tracking-wider">
                  Linked Incident Audits ({investigationData.related_incidents.length})
                </h3>
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {investigationData.related_incidents.map((inc) => (
                    <div key={inc.id} className="p-2 rounded bg-sage border border-bluegrey/40 flex items-center justify-between">
                      <span>Incident #{inc.id} - {inc.incident_type}</span>
                      <span className="text-forest">{inc.action_status}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer Buttons */}
            <div className="pt-4 flex items-center justify-between border-t border-bluegrey/25">
              <button
                onClick={() => navigate(`/intelligence?ip=${selectedThreat.src_ip}`)}
                className="px-4 py-2 rounded-lg bg-forest hover:bg-forest/90 text-white font-bold flex items-center gap-1.5 shadow-soft transition-all"
              >
                <span>Investigate IP Profile</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-2 rounded-lg bg-sage border border-bluegrey/50 text-muted hover:text-ink shadow-neumorph-sm"
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
