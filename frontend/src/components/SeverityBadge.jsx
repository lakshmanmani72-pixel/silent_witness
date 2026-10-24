import React from 'react';

const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'INFO').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-500/10 text-cyber-red border-cyber-red/40 shadow-[0_0_10px_rgba(255,53,94,0.25)]',
    HIGH: 'bg-amber-500/10 text-cyber-amber border-cyber-amber/40 shadow-[0_0_10px_rgba(255,176,32,0.2)]',
    MEDIUM: 'bg-blue-500/10 text-cyber-blue border-cyber-blue/40 shadow-[0_0_8px_rgba(59,130,246,0.15)]',
    LOW: 'bg-emerald-500/10 text-cyber-green border-cyber-green/40 shadow-[0_0_8px_rgba(0,255,163,0.15)]',
    INFO: 'bg-cyan-500/10 text-cyber-cyan border-cyber-cyan/40',
  };

  const currentStyle = styles[sev] || styles.INFO;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border font-mono-code ${currentStyle}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${
        sev === 'CRITICAL' ? 'bg-cyber-red animate-ping' :
        sev === 'HIGH' ? 'bg-cyber-amber' :
        sev === 'MEDIUM' ? 'bg-cyber-blue' :
        sev === 'LOW' ? 'bg-cyber-green' : 'bg-cyber-cyan'
      }`} />
      {sev}
    </span>
  );
};

export default SeverityBadge;
