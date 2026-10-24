import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

const StatCard = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'cyan',
  trend = null, // e.g. { direction: 'up', value: '+12%' }
}) => {
  const colorMap = {
    cyan: {
      border: 'border-cyber-cyan/30',
      text: 'text-cyber-cyan',
      bgIcon: 'bg-cyber-cyan/10',
      glow: 'shadow-[0_0_15px_rgba(0,245,255,0.12)]',
      accent: 'bg-cyber-cyan',
    },
    red: {
      border: 'border-cyber-red/30',
      text: 'text-cyber-red',
      bgIcon: 'bg-cyber-red/10',
      glow: 'shadow-[0_0_15px_rgba(255,53,94,0.15)]',
      accent: 'bg-cyber-red',
    },
    amber: {
      border: 'border-cyber-amber/30',
      text: 'text-cyber-amber',
      bgIcon: 'bg-cyber-amber/10',
      glow: 'shadow-[0_0_15px_rgba(255,176,32,0.15)]',
      accent: 'bg-cyber-amber',
    },
    green: {
      border: 'border-cyber-green/30',
      text: 'text-cyber-green',
      bgIcon: 'bg-cyber-green/10',
      glow: 'shadow-[0_0_15px_rgba(0,255,163,0.12)]',
      accent: 'bg-cyber-green',
    },
    blue: {
      border: 'border-cyber-blue/30',
      text: 'text-cyber-blue',
      bgIcon: 'bg-cyber-blue/10',
      glow: 'shadow-[0_0_15px_rgba(59,130,246,0.15)]',
      accent: 'bg-cyber-blue',
    },
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`relative bg-cyber-card border ${scheme.border} rounded-xl p-5 ${scheme.glow} transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden`}>
      {/* Top subtle line */}
      <div className={`absolute top-0 left-0 right-0 h-[2px] ${scheme.accent} opacity-60 group-hover:opacity-100 transition-opacity`} />

      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wider text-cyber-muted font-mono-code font-medium">
            {title}
          </p>
          <div className="text-2xl sm:text-3xl font-bold font-mono-code text-cyber-text tracking-tight">
            {value !== undefined && value !== null ? value : '--'}
          </div>
        </div>

        <div className={`p-3 rounded-lg ${scheme.bgIcon} ${scheme.text} border border-current/20 transition-transform group-hover:scale-105`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between text-xs font-mono-code">
        <span className="text-cyber-muted text-[11px] truncate max-w-[70%]">
          {subtitle}
        </span>

        {trend && (
          <div className={`flex items-center gap-1 font-semibold ${
            trend.direction === 'up' ? 'text-cyber-red' :
            trend.direction === 'down' ? 'text-cyber-green' : 'text-cyber-muted'
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
