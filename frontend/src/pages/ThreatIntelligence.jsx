import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  Layers,
  Lock,
  Unlock,
  Info,
  Clock,
  History,
  AlertTriangle,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { endpoints } from '../services/api';

const ThreatIntelligence = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [inputIP, setInputIP] = useState(searchParams.get('ip') || '');
  const [activeIP, setActiveIP] = useState(searchParams.get('ip') || '');
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Common quick-check IPs
  const sampleIPs = ['10.0.0.99', '172.16.5.200', '45.33.32.156', '198.51.100.77'];

  const fetchIntelligence = async (ip) => {
    if (!ip) return;
    try {
      setLoading(true);
      setError(null);
      const res = await endpoints.getIPIntelligence(ip.trim());
      setIntel(res.data);
      setActiveIP(ip.trim());
    } catch (err) {
      console.error('Failed to fetch threat intel:', err);
      setError('Could not retrieve local evidence records for this IP.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const queryIP = searchParams.get('ip') || '10.0.0.99';
    setInputIP(queryIP);
    fetchIntelligence(queryIP);
  }, [searchParams]);

  const handleSearch = (e) => {
    e.preventDefault();
    if (inputIP) {
      fetchIntelligence(inputIP);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-white font-mono-code flex items-center gap-2">
          <Search className="w-5 h-5 text-cyber-cyan" />
          Threat Intelligence Dossier
        </h1>
        <p className="text-xs text-cyber-muted mt-1">
          Forensic investigation of adversary behavior derived purely from local network observations.
        </p>
      </div>

      {/* Search Input Card */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg space-y-4">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-cyber-muted" />
            <input
              type="text"
              placeholder="Enter IP Address to investigate (e.g. 10.0.0.99)..."
              value={inputIP}
              onChange={(e) => setInputIP(e.target.value)}
              className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg pl-10 pr-4 py-2.5 text-xs font-mono-code text-cyber-text placeholder:text-cyber-muted/60 focus:outline-none focus:border-cyber-cyan shadow-inner"
            />
          </div>
          <button
            type="submit"
            className="px-6 py-2.5 rounded-lg bg-cyber-cyan hover:bg-cyan-400 text-black font-mono-code font-bold text-xs shadow-cyan-glow transition-all"
          >
            Investigate IP
          </button>
        </form>

        {/* Quick sample chips */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono-code text-cyber-muted">
          <span>Observed Attackers:</span>
          {sampleIPs.map((ip) => (
            <button
              key={ip}
              onClick={() => {
                setInputIP(ip);
                fetchIntelligence(ip);
              }}
              className="px-2.5 py-1 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-cyan hover:border-cyber-cyan transition-all"
            >
              {ip}
            </button>
          ))}
        </div>
      </div>

      {/* Intelligence Results Panel */}
      {loading ? (
        <div className="py-16 text-center text-cyber-muted font-mono-code text-xs space-y-3">
          <div className="w-8 h-8 rounded-full border-2 border-dashed border-cyber-cyan animate-spin mx-auto" />
          <p>Compiling forensic telemetry timeline...</p>
        </div>
      ) : error ? (
        <div className="p-4 bg-red-500/10 border border-cyber-red/30 rounded-xl text-xs font-mono-code text-cyber-red flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      ) : intel && intel.event_count > 0 ? (
        <div className="space-y-6 animate-fadeIn font-mono-code text-xs">
          {/* Top Dossier Summary Header */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow-xl relative overflow-hidden">
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
              <div>
                <span className="text-[10px] uppercase tracking-widest text-cyber-muted font-bold">
                  Locally Observed Host Target
                </span>
                <h2 className="text-2xl font-bold text-cyber-cyan mt-1 flex items-center gap-3">
                  {intel.ip}
                  <SeverityBadge severity={intel.highest_severity} />
                </h2>
              </div>

              {/* Block Status Pill */}
              <div className="flex items-center gap-3">
                {intel.block_status && intel.block_status.status === 'active' ? (
                  <div className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-cyber-red/40 text-cyber-red flex items-center gap-2 shadow-red-glow">
                    <Lock className="w-4 h-4" />
                    <span className="font-bold">STATUS: ACTIVELY BLOCKED</span>
                  </div>
                ) : (
                  <div className="px-3 py-1.5 rounded-lg bg-cyber-panel border border-cyber-border/40 text-cyber-muted flex items-center gap-2">
                    <Unlock className="w-4 h-4 text-cyber-green" />
                    <span>STATUS: NOT CURRENTLY BLOCKED</span>
                  </div>
                )}
              </div>
            </div>

            {/* Metrics Bar */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-cyber-border/30">
              <div>
                <span className="text-cyber-muted text-[11px]">Recorded Detections:</span>
                <p className="text-xl font-bold text-cyber-text mt-0.5">{intel.event_count}</p>
              </div>
              <div>
                <span className="text-cyber-muted text-[11px]">Observed Attack Vectors:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {intel.threat_types.map((type, idx) => (
                    <span key={idx} className="px-1.5 py-0.5 rounded bg-cyber-panel border border-cyber-border/40 text-white font-semibold text-[10px]">
                      {type}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-cyber-muted text-[11px]">First Observed:</span>
                <p className="text-cyber-text text-xs mt-0.5 truncate">
                  {intel.first_seen ? new Date(intel.first_seen).toUTCString() : '--'}
                </p>
              </div>
              <div>
                <span className="text-cyber-muted text-[11px]">Last Observed:</span>
                <p className="text-cyber-text text-xs mt-0.5 truncate">
                  {intel.last_seen ? new Date(intel.last_seen).toUTCString() : '--'}
                </p>
              </div>
            </div>
          </div>

          {/* Privacy & Attribution Notice */}
          <div className="p-4 bg-cyber-panel border border-cyber-border/30 rounded-xl text-cyber-muted text-xs font-sans leading-relaxed flex items-start gap-3">
            <Info className="w-5 h-5 text-cyber-cyan shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-cyber-text mb-0.5">Defensive Attribution Safeguard:</p>
              This intelligence is synthesized strictly from local metadata recorded on your network sensor. The application never sends queries to third-party threat services or transmits observed IP addresses externally. High connection frequency does not inherently indicate malicious intent; always correlate with operational context.
            </div>
          </div>

          {/* Incident Timeline */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg space-y-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2">
              <History className="w-4 h-4 text-cyber-cyan" />
              Incident Audit Timeline ({intel.related_incidents?.length || 0})
            </h3>

            {intel.related_incidents?.length === 0 ? (
              <p className="text-xs text-cyber-muted py-4">No formal security incidents linked to this IP.</p>
            ) : (
              <div className="space-y-2">
                {intel.related_incidents.map((inc) => (
                  <div
                    key={inc.id}
                    className="p-3 bg-cyber-panel/60 border border-cyber-border/30 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-cyber-muted text-[11px]">
                        {new Date(inc.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="font-bold text-cyber-text">Incident #{inc.id}</span>
                      <span className="text-cyber-cyan">{inc.incident_type}</span>
                    </div>

                    <div className="flex items-center gap-3">
                      <SeverityBadge severity={inc.severity} />
                      <span className="px-2 py-0.5 rounded bg-cyber-card border border-cyber-border/40 text-[10px] text-cyber-muted">
                        Status: {inc.action_status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : activeIP ? (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-12 text-center text-cyber-muted font-mono-code text-xs space-y-2">
          <ShieldCheck className="w-10 h-10 text-cyber-green mx-auto mb-2" />
          <p className="text-cyber-text text-sm font-bold">No Suspicious Behavior Observed for {activeIP}</p>
          <p>This IP address has not triggered any detection thresholds on this sensor.</p>
        </div>
      ) : (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-12 text-center text-cyber-muted font-mono-code text-xs">
          Select or enter an IP address above to review forensic intelligence.
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
