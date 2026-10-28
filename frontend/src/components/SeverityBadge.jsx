import React from 'react';

const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'INFO').toUpperCase();

  const styles = {
    CRITICAL: 'bg-bad/15 text-bad-ink border-bad/40 shadow-soft',
    HIGH: 'bg-amber/15 text-amber-ink border-amber/40 shadow-soft',
    MEDIUM: 'bg-bluegrey/15 text-bluegrey-ink border-bluegrey/40 shadow-soft',
    LOW: 'bg-good/15 text-good-ink border-good/40 shadow-soft',
    INFO: 'bg-forest/15 text-forest border-forest/40 shadow-soft',
  };

  const currentStyle = styles[sev] || styles.INFO;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider border font-mono-code ${currentStyle}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${
        sev === 'CRITICAL' ? 'bg-bad animate-ping' :
        sev === 'HIGH' ? 'bg-amber' :
        sev === 'MEDIUM' ? 'bg-bluegrey' :
        sev === 'LOW' ? 'bg-good' : 'bg-forest'
      }`} />
      {sev}
    </span>
  );
};

export default SeverityBadge;
