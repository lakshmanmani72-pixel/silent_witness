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
      <div className="py-12 flex flex-col items-center justify-center text-center text-[#B8C5D8] font-mono-code space-y-2">
        <div className="p-3 rounded-full bg-[#43D6A5]/10 border border-[#43D6A5]/30">
          <ShieldCheck className="w-8 h-8 text-[#43D6A5]" />
        </div>
        <p className="text-sm font-semibold text-[#F3F6FC]">No security incidents detected</p>
        <p className="text-xs text-[#B8C5D8]">Network traffic is currently clean and within safe baseline parameters.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs font-mono-code border-collapse">
        <thead>
          <tr className="border-b border-[#364D6E]/60 text-[#B8C5D8] uppercase text-[11px] tracking-wider bg-[#1E2F46]/80">
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
        <tbody className="divide-y divide-[#364D6E]/30">
          {threats.map((t) => {
            const isBlocked = t.response_status && t.response_status.includes('blocked');
            return (
              <tr
                key={t.id}
                className="hover:bg-[#253750]/60 transition-colors group"
              >
                <td className="py-3 px-4 text-[#B8C5D8] whitespace-nowrap">
                  {formatTime(t.timestamp)}
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <button
                    onClick={() => onInvestigateIP && onInvestigateIP(t.src_ip)}
                    className="font-bold text-[#43D6C5] hover:text-[#5B8DEF] hover:underline transition-colors"
                    title="Investigate IP in Threat Intelligence"
                  >
                    {t.src_ip}
                  </button>
                  {t.src_port && <span className="text-[#B8C5D8]/60 text-[10px]">:{t.src_port}</span>}
                </td>

                <td className="py-3 px-4 text-[#B8C5D8] whitespace-nowrap">
                  {t.dst_ip ? (
                    <span>
                      {t.dst_ip}
                      {t.dst_port && <span className="text-[#B8C5D8]/60 text-[10px]">:{t.dst_port}</span>}
                    </span>
                  ) : (
                    '--'
                  )}
                </td>

                <td className="py-3 px-4 text-[#F3F6FC] whitespace-nowrap">
                  <span className="font-semibold">{t.threat_type}</span>
                  {t.protocol && (
                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[10px] bg-[#1E2F46] border border-[#364D6E]/60 text-[#B8C5D8]">
                      {t.protocol}
                    </span>
                  )}
                </td>

                <td className="py-3 px-4 font-bold text-[#F3F6FC] whitespace-nowrap">
                  {t.count || 1}
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <SeverityBadge severity={t.severity} />
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                    isBlocked
                      ? 'bg-[#FF7185]/15 text-[#FF7185] border border-[#FF7185]/30'
                      : 'bg-[#1E2F46] text-[#B8C5D8] border border-[#364D6E]/40'
                  }`}>
                    {isBlocked ? <ShieldAlert className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                    {t.response_status || 'monitored'}
                  </span>
                </td>

                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <button
                    onClick={() => onViewDetails && onViewDetails(t)}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#253750] hover:bg-[#5B8DEF] hover:text-[#F3F6FC] border border-[#364D6E]/60 hover:border-[#5B8DEF] text-[#F3F6FC] transition-all shadow-neumorph-sm font-medium"
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
