import React from 'react';

const StatusIndicator = ({ status, text, pulse = true }) => {
  const colors = {
    active: 'bg-[#43D6A5] text-[#43D6A5] border-[#43D6A5]/40',
    simulation: 'bg-[#43D6C5] text-[#43D6C5] border-[#43D6C5]/40',
    warning: 'bg-[#F5BD61] text-[#F5BD61] border-[#F5BD61]/40',
    danger: 'bg-[#FF7185] text-[#FF7185] border-[#FF7185]/40',
    offline: 'bg-[#B8C5D8]/40 text-[#B8C5D8] border-[#364D6E]',
  };

  const current = colors[status] || colors.offline;

  return (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#253750]/80 border border-[#364D6E]/50 text-xs font-mono-code shadow-neumorph-sm">
      <span className="relative flex h-2 w-2">
        {pulse && status !== 'offline' && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${current.split(' ')[0]}`} />
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${current.split(' ')[0]}`} />
      </span>
      <span className={current.split(' ')[1]}>{text}</span>
    </div>
  );
};

export default StatusIndicator;
