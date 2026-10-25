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
        <h1 className="text-xl font-bold tracking-tight text-[#F3F6FC] font-mono-code flex items-center gap-2">
          <Search className="w-5 h-5 text-[#43D6C5]" />
          Threat Intelligence Dossier
        </h1>
        <p className="text-xs text-[#B8C5D8] mt-1">
          Forensic investigation of adversary behavior derived purely from local network observations.
        </p>
      </div>

      {/* Search Input Card */}
      <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card space-y-4 relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#5B8DEF] via-[#43D6C5] to-[#B3A0FF] opacity-60" />

        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#B8C5D8]" />
            <input
              type="text"
              placeholder="Enter IP Address to investigate (e.g. 10.0.0.99)..."
              value={inputIP}
              onChange={(e) => setInputIP(e.target.value)}
              className="w-full bg-[#1E2F46] border border-[#364D6E]/60 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono-code text-[#F3F6FC] placeholder:text-[#B8C5D8]/50 focus:outline-none focus:border-[#5B8DEF] shadow-neumorph-inset"
            />
          </div>
          <button
            type="submit"
            className="px-6 py-2.5 rounded-xl bg-[#5B8DEF] hover:bg-[#5B8DEF]/90 text-white font-mono-code font-bold text-xs shadow-[0_0_15px_rgba(91,141,239,0.3)] transition-all"
          >
            Investigate IP
          </button>
        </form>

        {/* Quick sample chips with soft neumorphic styling */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono-code text-[#B8C5D8]">
          <span>Observed Attackers:</span>
          {sampleIPs.map((ip) => (
            <button
              key={ip}
              onClick={() => {
                setInputIP(ip);
                fetchIntelligence(ip);
              }}
              className="px-3 py-1 rounded-lg bg-[#1E2F46] border border-[#364D6E]/50 text-[#43D6C5] hover:border-[#5B8DEF] hover:text-[#F3F6FC] transition-all shadow-neumorph-sm"
            >
              {ip}
            </button>
          ))}
        </div>
      </div>

      {/* Intelligence Results Panel */}
      {loading ? (
        <div className="py-16 text-center text-[#B8C5D8] font-mono-code text-xs space-y-3">
          <div className="w-8 h-8 rounded-full border-2 border-dashed border-[#43D6C5] animate-spin mx-auto" />
          <p>Compiling forensic telemetry timeline...</p>
        </div>
      ) : error ? (
        <div className="p-4 bg-[#FF7185]/10 border border-[#FF7185]/30 rounded-xl text-xs font-mono-code text-[#FF7185] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      ) : intel && intel.event_count > 0 ? (
        <div className="space-y-6 animate-fadeIn font-mono-code text-xs">
          {/* Top Dossier Summary Header */}
          <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-6 shadow-aurora-card relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-[#43D6C5] via-[#5B8DEF] to-[#FF7185]" />

            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
              <div>
                <span className="text-[10px] uppercase tracking-widest text-[#B8C5D8] font-bold">
                  Locally Observed Host Target
                </span>
                <h2 className="text-2xl font-bold text-[#43D6C5] mt-1 flex items-center gap-3">
                  {intel.ip}
                  <SeverityBadge severity={intel.highest_severity} />
                </h2>
              </div>

              {/* Block Status Pill */}
              <div className="flex items-center gap-3">
                {intel.block_status && intel.block_status.status === 'active' ? (
                  <div className="px-3.5 py-1.5 rounded-xl bg-[#FF7185]/15 border border-[#FF7185]/40 text-[#FF7185] flex items-center gap-2 shadow-[0_0_12px_rgba(255,113,133,0.25)]">
                    <Lock className="w-4 h-4" />
                    <span className="font-bold">STATUS: ACTIVELY BLOCKED</span>
                  </div>
                ) : (
                  <div className="px-3.5 py-1.5 rounded-xl bg-[#1E2F46] border border-[#364D6E]/50 text-[#B8C5D8] flex items-center gap-2 shadow-neumorph-sm">
                    <Unlock className="w-4 h-4 text-[#43D6A5]" />
                    <span>STATUS: NOT CURRENTLY BLOCKED</span>
                  </div>
                )}
              </div>
            </div>

            {/* Metrics Bar */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-white/[0.08]">
              <div>
                <span className="text-[#B8C5D8] text-[11px]">Recorded Detections:</span>
                <p className="text-xl font-bold text-[#F3F6FC] mt-0.5">{intel.event_count}</p>
              </div>
              <div>
                <span className="text-[#B8C5D8] text-[11px]">Observed Attack Vectors:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {intel.threat_types.map((type, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-[#1E2F46] border border-[#364D6E]/50 text-[#F3F6FC] font-semibold text-[10px]">
                      {type}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-[#B8C5D8] text-[11px]">First Observed:</span>
                <p className="text-[#F3F6FC] text-xs mt-0.5 truncate">
                  {intel.first_seen ? new Date(intel.first_seen).toUTCString() : '--'}
                </p>
              </div>
              <div>
                <span className="text-[#B8C5D8] text-[11px]">Last Observed:</span>
                <p className="text-[#F3F6FC] text-xs mt-0.5 truncate">
                  {intel.last_seen ? new Date(intel.last_seen).toUTCString() : '--'}
                </p>
              </div>
            </div>
          </div>

          {/* Privacy & Attribution Notice */}
          <div className="p-4 bg-[#1E2F46] border border-[#364D6E]/50 rounded-xl text-[#B8C5D8] text-xs font-sans leading-relaxed flex items-start gap-3 shadow-neumorph-inset">
            <Info className="w-5 h-5 text-[#43D6C5] shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-[#F3F6FC] mb-0.5 font-mono-code">Defensive Attribution Safeguard:</p>
              This intelligence is synthesized strictly from local metadata recorded on your network sensor. The application never sends queries to third-party threat services or transmits observed IP addresses externally. High connection frequency does not inherently indicate malicious intent; always correlate with operational context.
            </div>
          </div>

          {/* Incident Timeline */}
          <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card space-y-4">
            <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2">
              <History className="w-4 h-4 text-[#43D6C5]" />
              Incident Audit Timeline ({intel.related_incidents?.length || 0})
            </h3>

            {intel.related_incidents?.length === 0 ? (
              <p className="text-xs text-[#B8C5D8] py-4">No formal security incidents linked to this IP.</p>
            ) : (
              <div className="space-y-2">
                {intel.related_incidents.map((inc) => (
                  <div
                    key={inc.id}
                    className="p-3 bg-[#1E2F46] border border-[#364D6E]/40 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs shadow-neumorph-sm"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-[#B8C5D8] text-[11px]">
                        {new Date(inc.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="font-bold text-[#F3F6FC]">Incident #{inc.id}</span>
                      <span className="text-[#43D6C5]">{inc.incident_type}</span>
                    </div>

                    <div className="flex items-center gap-3">
                      <SeverityBadge severity={inc.severity} />
                      <span className="px-2 py-0.5 rounded bg-[#253750] border border-[#364D6E]/40 text-[10px] text-[#B8C5D8]">
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
        <div className="bg-[#2B3F59]/80 border border-[#364D6E]/70 rounded-xl p-12 text-center text-[#B8C5D8] font-mono-code text-xs space-y-2 shadow-aurora-card">
          <ShieldCheck className="w-10 h-10 text-[#43D6A5] mx-auto mb-2" />
          <p className="text-[#F3F6FC] text-sm font-bold">No Suspicious Behavior Observed for {activeIP}</p>
          <p>This IP address has not triggered any detection thresholds on this sensor.</p>
        </div>
      ) : (
        <div className="bg-[#2B3F59]/80 border border-[#364D6E]/70 rounded-xl p-12 text-center text-[#B8C5D8] font-mono-code text-xs shadow-aurora-card">
          Select or enter an IP address above to review forensic intelligence.
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
