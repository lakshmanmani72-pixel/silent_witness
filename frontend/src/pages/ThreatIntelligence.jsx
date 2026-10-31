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
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-ink font-mono-code flex items-center gap-2">
          <Search className="w-5 h-5 text-forest" />
          Threat Intelligence Dossier
        </h1>
        <p className="text-xs text-muted mt-1">
          Forensic investigation of adversary behavior derived purely from local network observations.
        </p>
      </div>

      {/* Search Input Card */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4 relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-bluegrey via-forest to-bluegrey opacity-60" />

        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              placeholder="Enter IP Address to investigate (e.g. 10.0.0.99)..."
              value={inputIP}
              onChange={(e) => setInputIP(e.target.value)}
              className="w-full bg-surface border border-bluegrey/40 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono-code text-ink placeholder:text-muted/50 focus:outline-none focus:border-bluegrey shadow-neumorph-inset"
            />
          </div>
          <button
            type="submit"
            className="px-6 py-2.5 rounded-xl bg-forest hover:bg-forest/90 text-white font-mono-code font-bold text-xs shadow-soft transition-all"
          >
            Investigate IP
          </button>
        </form>

        {/* Quick sample chips with soft neumorphic styling */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono-code text-muted">
          <span>Observed Attackers:</span>
          {sampleIPs.map((ip) => (
            <button
              key={ip}
              onClick={() => {
                setInputIP(ip);
                fetchIntelligence(ip);
              }}
              className="px-3 py-1 rounded-lg bg-sage border border-bluegrey/50 text-forest hover:border-bluegrey hover:text-ink transition-all shadow-neumorph-sm"
            >
              {ip}
            </button>
          ))}
        </div>
      </div>

      {/* Intelligence Results Panel */}
      {loading ? (
        <div className="py-16 text-center text-muted font-mono-code text-xs space-y-3">
          <div className="w-8 h-8 rounded-full border-2 border-dashed border-forest animate-spin mx-auto" />
          <p>Compiling forensic telemetry timeline...</p>
        </div>
      ) : error ? (
        <div className="p-4 bg-bad/10 border border-bad/30 rounded-xl text-xs font-mono-code text-bad-ink flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      ) : intel && intel.event_count > 0 ? (
        <div className="space-y-6 animate-fadeIn font-mono-code text-xs">
          {/* Top Dossier Summary Header */}
          <div className="bg-surface border border-bluegrey/40 rounded-xl p-6 shadow-soft relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-forest via-bluegrey to-bad" />

            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
              <div>
                <span className="text-[10px] uppercase tracking-widest text-muted font-bold">
                  Locally Observed Host Target
                </span>
                <h2 className="text-2xl font-bold text-forest mt-1 flex items-center gap-3">
                  {intel.ip}
                  <SeverityBadge severity={intel.highest_severity} />
                </h2>
              </div>

              {/* Block Status Pill */}
              <div className="flex items-center gap-3">
                {intel.block_status && intel.block_status.status === 'active' ? (
                  <div className="px-3.5 py-1.5 rounded-xl bg-bad/15 border border-bad/40 text-bad-ink flex items-center gap-2 shadow-soft">
                    <Lock className="w-4 h-4" />
                    <span className="font-bold">STATUS: ACTIVELY BLOCKED</span>
                  </div>
                ) : (
                  <div className="px-3.5 py-1.5 rounded-xl bg-sage border border-bluegrey/50 text-muted flex items-center gap-2 shadow-neumorph-sm">
                    <Unlock className="w-4 h-4 text-good-ink" />
                    <span>STATUS: NOT CURRENTLY BLOCKED</span>
                  </div>
                )}
              </div>
            </div>

            {/* Metrics Bar */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-bluegrey/25">
              <div>
                <span className="text-muted text-[11px]">Recorded Detections:</span>
                <p className="text-xl font-bold text-ink mt-0.5">{intel.event_count}</p>
              </div>
              <div>
                <span className="text-muted text-[11px]">Observed Attack Vectors:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {intel.threat_types.map((type, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-sage border border-bluegrey/50 text-ink font-semibold text-[10px]">
                      {type}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-muted text-[11px]">First Observed:</span>
                <p className="text-ink text-xs mt-0.5 truncate">
                  {intel.first_seen ? new Date(intel.first_seen).toUTCString() : '--'}
                </p>
              </div>
              <div>
                <span className="text-muted text-[11px]">Last Observed:</span>
                <p className="text-ink text-xs mt-0.5 truncate">
                  {intel.last_seen ? new Date(intel.last_seen).toUTCString() : '--'}
                </p>
              </div>
            </div>
          </div>

          {/* Privacy & Attribution Notice */}
          <div className="p-4 bg-sage border border-bluegrey/50 rounded-xl text-muted text-xs font-sans leading-relaxed flex items-start gap-3 shadow-neumorph-inset">
            <Info className="w-5 h-5 text-forest shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-ink mb-0.5 font-mono-code">Defensive Attribution Safeguard:</p>
              This intelligence is synthesized strictly from local metadata recorded on your network sensor. The application never sends queries to third-party threat services or transmits observed IP addresses externally. High connection frequency does not inherently indicate malicious intent; always correlate with operational context.
            </div>
          </div>

          {/* Incident Timeline */}
          <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4">
            <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-ink font-mono-code flex items-center gap-2">
              <History className="w-4 h-4 text-forest" />
              Incident Audit Timeline ({intel.related_incidents?.length || 0})
            </h3>

            {intel.related_incidents?.length === 0 ? (
              <p className="text-xs text-muted py-4">No formal security incidents linked to this IP.</p>
            ) : (
              <div className="space-y-2">
                {intel.related_incidents.map((inc) => (
                  <div
                    key={inc.id}
                    className="p-3 bg-sage border border-bluegrey/40 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs shadow-neumorph-sm"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-muted text-[11px]">
                        {new Date(inc.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="font-bold text-ink">Incident #{inc.id}</span>
                      <span className="text-forest">{inc.incident_type}</span>
                    </div>

                    <div className="flex items-center gap-3">
                      <SeverityBadge severity={inc.severity} />
                      <span className="px-2 py-0.5 rounded bg-sage border border-bluegrey/40 text-[10px] text-muted">
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
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-12 text-center text-muted font-mono-code text-xs space-y-2 shadow-soft">
          <ShieldCheck className="w-10 h-10 text-good-ink mx-auto mb-2" />
          <p className="text-ink text-sm font-bold">No Suspicious Behavior Observed for {activeIP}</p>
          <p>This IP address has not triggered any detection thresholds on this sensor.</p>
        </div>
      ) : (
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-12 text-center text-muted font-mono-code text-xs shadow-soft">
          Select or enter an IP address above to review forensic intelligence.
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
