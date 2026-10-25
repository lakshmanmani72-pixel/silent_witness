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
      border: 'border-[#5B8DEF]/30',
      text: 'text-[#5B8DEF]',
      bgIcon: 'bg-[#5B8DEF]/10 border-[#5B8DEF]/30',
      glow: 'shadow-[0_4px_20px_rgba(91,141,239,0.12)]',
      accent: 'bg-gradient-to-r from-[#5B8DEF] to-[#43D6C5]',
    },
    cyan: {
      border: 'border-[#43D6C5]/30',
      text: 'text-[#43D6C5]',
      bgIcon: 'bg-[#43D6C5]/10 border-[#43D6C5]/30',
      glow: 'shadow-[0_4px_20px_rgba(67,214,197,0.12)]',
      accent: 'bg-gradient-to-r from-[#43D6C5] to-[#5B8DEF]',
    },
    red: {
      border: 'border-[#FF7185]/35',
      text: 'text-[#FF7185]',
      bgIcon: 'bg-[#FF7185]/10 border-[#FF7185]/30',
      glow: 'shadow-[0_4px_20px_rgba(255,113,133,0.14)]',
      accent: 'bg-gradient-to-r from-[#FF7185] to-[#F5BD61]',
    },
    amber: {
      border: 'border-[#F5BD61]/35',
      text: 'text-[#F5BD61]',
      bgIcon: 'bg-[#F5BD61]/10 border-[#F5BD61]/30',
      glow: 'shadow-[0_4px_20px_rgba(245,189,97,0.12)]',
      accent: 'bg-gradient-to-r from-[#F5BD61] to-[#FF7185]',
    },
    green: {
      border: 'border-[#43D6A5]/35',
      text: 'text-[#43D6A5]',
      bgIcon: 'bg-[#43D6A5]/10 border-[#43D6A5]/30',
      glow: 'shadow-[0_4px_20px_rgba(67,214,165,0.12)]',
      accent: 'bg-gradient-to-r from-[#43D6A5] to-[#43D6C5]',
    },
    purple: {
      border: 'border-[#B3A0FF]/35',
      text: 'text-[#B3A0FF]',
      bgIcon: 'bg-[#B3A0FF]/10 border-[#B3A0FF]/30',
      glow: 'shadow-[0_4px_20px_rgba(179,160,255,0.12)]',
      accent: 'bg-gradient-to-r from-[#B3A0FF] to-[#5B8DEF]',
    },
  };

  const scheme = colorMap[color] || colorMap.blue;

  return (
    <div className={`relative bg-[#2B3F59]/80 backdrop-blur-md border ${scheme.border} rounded-xl p-5 ${scheme.glow} transition-all duration-300 hover:-translate-y-1 hover:border-[#5B8DEF]/40 group overflow-hidden shadow-aurora-card`}>
      {/* Top subtle aurora line */}
      <div className={`absolute top-0 left-0 right-0 h-[2px] ${scheme.accent} opacity-70 group-hover:opacity-100 transition-opacity`} />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-white/20 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-white/20 pointer-events-none" />

      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-[#B8C5D8] font-mono-code font-medium">
            {title}
          </p>
          <div className="text-2xl sm:text-3xl font-bold font-mono-code text-[#F3F6FC] tracking-tight">
            {value !== undefined && value !== null ? value : '--'}
          </div>
        </div>

        <div className={`p-2.5 rounded-xl ${scheme.bgIcon} ${scheme.text} border shadow-neumorph-sm transition-transform group-hover:scale-105`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      <div className="mt-4 pt-2 border-t border-white/[0.06] flex items-center justify-between text-xs font-mono-code">
        <span className="text-[#B8C5D8]/80 text-[11px] truncate max-w-[70%]">
          {subtitle}
        </span>

        {trend && (
          <div className={`flex items-center gap-1 font-semibold text-[11px] px-1.5 py-0.5 rounded ${
            trend.direction === 'up' && color === 'red' ? 'text-[#FF7185] bg-[#FF7185]/10' :
            trend.direction === 'up' ? 'text-[#43D6A5] bg-[#43D6A5]/10' :
            trend.direction === 'down' ? 'text-[#43D6A5] bg-[#43D6A5]/10' : 'text-[#B8C5D8] bg-[#1E2F46]'
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
