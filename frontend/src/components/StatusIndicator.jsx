import React from 'react';

const StatusIndicator = ({ status, text, pulse = true }) => {
  const colors = {
    active: 'bg-cyber-green text-cyber-green border-cyber-green/40',
    simulation: 'bg-cyber-cyan text-cyber-cyan border-cyber-cyan/40',
    warning: 'bg-cyber-amber text-cyber-amber border-cyber-amber/40',
    danger: 'bg-cyber-red text-cyber-red border-cyber-red/40',
    offline: 'bg-gray-500 text-gray-400 border-gray-600',
  };

  const current = colors[status] || colors.offline;

  return (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-cyber-card/80 border border-cyber-border/40 text-xs font-mono-code">
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
