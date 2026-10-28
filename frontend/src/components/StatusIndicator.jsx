import React from 'react';

const StatusIndicator = ({ status, text, pulse = true }) => {
  const colors = {
    active: 'bg-good text-good-ink border-good/40',
    simulation: 'bg-forest text-forest border-forest/40',
    warning: 'bg-amber text-amber-ink border-amber/40',
    danger: 'bg-bad text-bad-ink border-bad/40',
    offline: 'bg-muted/40 text-muted border-bluegrey',
  };

  const current = colors[status] || colors.offline;

  return (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-sage/80 border border-bluegrey/50 text-xs font-mono-code shadow-neumorph-sm">
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
