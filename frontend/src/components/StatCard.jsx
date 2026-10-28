import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

const StatCard = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'blue',
  trend = null,
}) => {
  const colorMap = {
    blue: {
      border: 'border-bluegrey/30',
      text: 'text-bluegrey-ink',
      bgIcon: 'bg-bluegrey/10 border-bluegrey/30',
      glow: 'shadow-soft',
      accent: 'bg-gradient-to-r from-bluegrey to-forest',
    },
    cyan: {
      border: 'border-forest/30',
      text: 'text-forest',
      bgIcon: 'bg-forest/10 border-forest/30',
      glow: 'shadow-soft',
      accent: 'bg-gradient-to-r from-forest to-bluegrey',
    },
    red: {
      border: 'border-bad/35',
      text: 'text-bad-ink',
      bgIcon: 'bg-bad/10 border-bad/30',
      glow: 'shadow-soft',
      accent: 'bg-gradient-to-r from-bad to-amber',
    },
    amber: {
      border: 'border-amber/35',
      text: 'text-amber-ink',
      bgIcon: 'bg-amber/10 border-amber/30',
      glow: 'shadow-soft',
      accent: 'bg-gradient-to-r from-amber to-bad',
    },
    green: {
      border: 'border-good/35',
      text: 'text-good-ink',
      bgIcon: 'bg-good/10 border-good/30',
      glow: 'shadow-soft',
      accent: 'bg-gradient-to-r from-good to-forest',
    },
    purple: {
      border: 'border-bluegrey/35',
      text: 'text-bluegrey-ink',
      bgIcon: 'bg-bluegrey/10 border-bluegrey/30',
      glow: 'shadow-soft',
      accent: 'bg-gradient-to-r from-bluegrey to-bluegrey',
    },
  };

  const scheme = colorMap[color] || colorMap.blue;

  return (
    <div className={`relative bg-surface border ${scheme.border} rounded-xl p-5 ${scheme.glow} transition-all duration-300 hover:border-bluegrey/40 group overflow-hidden shadow-soft`}>
      {/* Top subtle aurora line */}
      <div className={`absolute top-0 left-0 right-0 h-[2px] ${scheme.accent} opacity-70 group-hover:opacity-100 transition-opacity`} />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-bluegrey/25 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-bluegrey/25 pointer-events-none" />

      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-muted font-mono-code font-medium">
            {title}
          </p>
          <div className="text-2xl sm:text-3xl font-bold font-mono-code text-ink tracking-tight">
            {value !== undefined && value !== null ? value : '--'}
          </div>
        </div>

        <div className={`p-2.5 rounded-xl ${scheme.bgIcon} ${scheme.text} border shadow-neumorph-sm transition-transform`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      <div className="mt-4 pt-2 border-t border-bluegrey/25 flex items-center justify-between text-xs font-mono-code">
        <span className="text-muted/80 text-[11px] truncate max-w-[70%]">
          {subtitle}
        </span>

        {trend && (
          <div className={`flex items-center gap-1 font-semibold text-[11px] px-1.5 py-0.5 rounded ${
            trend.direction === 'up' && color === 'red' ? 'text-bad-ink bg-bad/10' :
            trend.direction === 'up' ? 'text-good-ink bg-good/10' :
            trend.direction === 'down' ? 'text-good-ink bg-good/10' : 'text-muted bg-sage'
          }`}>
            {trend.direction === 'up' && <TrendingUp className="w-3 h-3" />}
            {trend.direction === 'down' && <TrendingDown className="w-3 h-3" />}
            {trend.direction === 'neutral' && <Minus className="w-3 h-3" />}
            <span>{trend.value}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default StatCard;
