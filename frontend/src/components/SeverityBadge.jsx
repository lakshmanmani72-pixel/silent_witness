import React from 'react';

const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'INFO').toUpperCase();

  const styles = {
    CRITICAL: 'bg-[#FF7185]/15 text-[#FF7185] border-[#FF7185]/40 shadow-[0_0_12px_rgba(255,113,133,0.2)]',
    HIGH: 'bg-[#F5BD61]/15 text-[#F5BD61] border-[#F5BD61]/40 shadow-[0_0_12px_rgba(245,189,97,0.18)]',
    MEDIUM: 'bg-[#5B8DEF]/15 text-[#5B8DEF] border-[#5B8DEF]/40 shadow-[0_0_10px_rgba(91,141,239,0.15)]',
    LOW: 'bg-[#43D6A5]/15 text-[#43D6A5] border-[#43D6A5]/40 shadow-[0_0_10px_rgba(67,214,165,0.15)]',
    INFO: 'bg-[#43D6C5]/15 text-[#43D6C5] border-[#43D6C5]/40 shadow-[0_0_10px_rgba(67,214,197,0.15)]',
  };

  const currentStyle = styles[sev] || styles.INFO;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider border font-mono-code ${currentStyle}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${
        sev === 'CRITICAL' ? 'bg-[#FF7185] animate-ping' :
        sev === 'HIGH' ? 'bg-[#F5BD61]' :
        sev === 'MEDIUM' ? 'bg-[#5B8DEF]' :
        sev === 'LOW' ? 'bg-[#43D6A5]' : 'bg-[#43D6C5]'
      }`} />
      {sev}
    </span>
  );
};

export default SeverityBadge;
