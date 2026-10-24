import React from 'react';
import SeverityBadge from './SeverityBadge';
import { Eye, ShieldCheck, ShieldAlert, Clock } from 'lucide-react';

const ThreatTable = ({ threats = [], onViewDetails, onInvestigateIP }) => {
  const formatTime = (ts) => {
    if (!ts) return '--';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  };

  if (!threats || threats.length === 0) {
    return (
      <div className="py-12 flex flex-col items-center justify-center text-center text-cyber-muted font-mono-code space-y-2">
        <ShieldCheck className="w-10 h-10 text-cyber-green/60" />
        <p className="text-sm text-cyber-text">No security incidents detected</p>
        <p className="text-xs text-cyber-muted">Network traffic is currently clean and within safe baseline parameters.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs font-mono-code border-collapse">
        <thead>
          <tr className="border-b border-cyber-border/40 text-cyber-muted uppercase text-[11px] tracking-wider bg-cyber-panel/50">
            <th className="py-3 px-4 font-semibold">Timestamp</th>
            <th className="py-3 px-4 font-semibold">Source IP</th>
            <th className="py-3 px-4 font-semibold">Destination</th>
            <th className="py-3 px-4 font-semibold">Threat Type</th>
            <th className="py-3 px-4 font-semibold">Count</th>
            <th className="py-3 px-4 font-semibold">Severity</th>
            <th className="py-3 px-4 font-semibold">Response</th>
            <th className="py-3 px-4 font-semibold text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-cyber-border/20">
          {threats.map((t) => {
            const isBlocked = t.response_status && t.response_status.includes('blocked');
            return (
              <tr
                key={t.id}
                className="hover:bg-cyber-panel/60 transition-colors group"
              >
                <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                  {formatTime(t.timestamp)}
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <button
                    onClick={() => onInvestigateIP && onInvestigateIP(t.src_ip)}
                    className="font-bold text-cyber-cyan hover:underline decoration-cyber-cyan/50 hover:text-cyan-300 transition-colors"
                    title="Investigate IP in Threat Intelligence"
                  >
                    {t.src_ip}
                  </button>
                  {t.src_port && <span className="text-cyber-muted/60 text-[10px]">:{t.src_port}</span>}
                </td>

                <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                  {t.dst_ip ? (
                    <span>
                      {t.dst_ip}
                      {t.dst_port && <span className="text-cyber-muted/60 text-[10px]">:{t.dst_port}</span>}
                    </span>
                  ) : (
                    '--'
                  )}
                </td>

                <td className="py-3 px-4 text-cyber-text whitespace-nowrap">
                  <span className="font-semibold text-white/90">{t.threat_type}</span>
                  {t.protocol && (
                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[10px] bg-cyber-card border border-cyber-border/40 text-cyber-muted">
                      {t.protocol}
                    </span>
                  )}
                </td>

                <td className="py-3 px-4 font-bold text-cyber-text whitespace-nowrap">
                  {t.count || 1}
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <SeverityBadge severity={t.severity} />
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                    isBlocked
                      ? 'bg-red-500/10 text-cyber-red border border-cyber-red/30'
                      : 'bg-cyber-panel text-cyber-muted border border-cyber-border/30'
                  }`}>
                    {isBlocked ? <ShieldAlert className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                    {t.response_status || 'monitored'}
                  </span>
                </td>

                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <button
                    onClick={() => onViewDetails && onViewDetails(t)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyber-card hover:bg-cyber-cyan hover:text-black border border-cyber-border/40 hover:border-cyber-cyan text-cyber-text transition-all shadow-sm"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>Details</span>
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default ThreatTable;
