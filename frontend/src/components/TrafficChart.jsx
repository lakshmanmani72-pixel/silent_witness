import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    const formattedTime = label ? new Date(label).toLocaleTimeString() : '';
    return (
      <div className="bg-cyber-panel/95 border border-cyber-border/60 p-3 rounded-lg shadow-2xl backdrop-blur-md text-xs font-mono-code space-y-1.5">
        <p className="text-cyber-muted font-bold pb-1 border-b border-cyber-border/30">
          Timestamp: {formattedTime || label}
        </p>
        {payload.map((item, index) => (
          <div key={index} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-cyber-text" style={{ color: item.color }}>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
              {item.name}:
            </span>
            <span className="font-bold text-cyber-text">
              {item.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

const TrafficChart = ({ data = [], timeRange = '5m', onTimeRangeChange }) => {
  const ranges = [
    { label: '5m', value: '5m' },
    { label: '15m', value: '15m' },
    { label: '1h', value: '1h' },
    { label: '24h', value: '24h' },
  ];

  const formatXAxis = (tickItem) => {
    if (!tickItem) return '';
    try {
      const d = new Date(tickItem);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return tickItem;
    }
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg relative">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse" />
            Network Traffic Volume & Threat Rate
          </h3>
          <p className="text-xs text-cyber-muted mt-0.5">
            Real-time packet inspection & telemetry
          </p>
        </div>

        {/* Time-range pills */}
        <div className="flex items-center gap-1 bg-cyber-panel p-1 rounded-lg border border-cyber-border/40 font-mono-code text-xs">
          {ranges.map((r) => (
            <button
              key={r.value}
              onClick={() => onTimeRangeChange && onTimeRangeChange(r.value)}
              className={`px-2.5 py-1 rounded transition-all ${
                timeRange === r.value
                  ? 'bg-cyber-cyan text-black font-bold shadow-cyan-glow'
                  : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-card/60'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="h-64 sm:h-72 w-full">
        {data.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-cyber-muted text-xs font-mono-code space-y-2">
            <span className="w-8 h-8 rounded-full border border-dashed border-cyber-cyan/40 animate-spin" />
            <p>Awaiting network telemetry packets...</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00F5FF" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#00F5FF" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#FFB020" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#FFB020" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#FF355E" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="#FF355E" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 245, 255, 0.07)" vertical={false} />
              <XAxis
                dataKey="timestamp"
                tickFormatter={formatXAxis}
                stroke="#64748B"
                tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
              />
              <YAxis
                stroke="#64748B"
                tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                iconType="circle"
                wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingBottom: '10px' }}
              />

              <Area
                type="monotone"
                dataKey="packets_observed"
                name="Total Packets"
                stroke="#00F5FF"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorPackets)"
              />
              <Area
                type="monotone"
                dataKey="suspicious_packets"
                name="Suspicious"
                stroke="#FFB020"
                strokeWidth={1.5}
                fillOpacity={1}
                fill="url(#colorSuspicious)"
              />
              <Area
                type="monotone"
                dataKey="threats_detected"
                name="Threats Detected"
                stroke="#FF355E"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorThreats)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};

export default TrafficChart;
