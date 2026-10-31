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
      <div className="bg-sage/95 border border-bluegrey/30 p-3 rounded-xl shadow-soft text-xs font-mono-code space-y-1.5">
        <p className="text-muted font-semibold pb-1.5 border-b border-bluegrey/25">
          Telemetry Timestamp: {formattedTime || label}
        </p>
        {payload.map((item, index) => (
          <div key={index} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5" style={{ color: item.color }}>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
              {item.name}:
            </span>
            <span className="font-bold text-ink">
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
    <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft relative overflow-hidden">
      {/* Top subtle aurora gradient line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-bluegrey via-forest to-bluegrey opacity-60" />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-bluegrey/25 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-bluegrey/25 pointer-events-none" />

      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-5">
        <div>
          <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-ink font-mono-code flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-forest shadow-soft" />
            Network Traffic Volume & Threat Rate
          </h3>
          <p className="text-xs text-muted mt-0.5">
            Real-time packet inspection & telemetry throughput
          </p>
        </div>

        {/* Time-range pills with soft neumorphism */}
        <div className="flex items-center gap-1 bg-sage p-1 rounded-lg border border-bluegrey/50 font-mono-code text-xs shadow-neumorph-inset">
          {ranges.map((r) => (
            <button
              key={r.value}
              onClick={() => onTimeRangeChange && onTimeRangeChange(r.value)}
              className={`px-3 py-1 rounded transition-all text-xs font-semibold ${
                timeRange === r.value
                  ? 'bg-forest text-white shadow-soft'
                  : 'text-muted hover:text-ink hover:bg-sage'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="h-64 sm:h-72 w-full">
        {data.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-muted text-xs font-mono-code space-y-2">
            <span className="w-8 h-8 rounded-full border border-dashed border-forest/50 animate-spin" />
            <p>Awaiting network telemetry packets...</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8296A5" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#8296A5" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#C5A66D" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#C5A66D" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#C87878" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#C87878" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="rgba(130,150,165, 0.10)" vertical={false} />
              <XAxis
                dataKey="timestamp"
                tickFormatter={formatXAxis}
                stroke="#B4C0C8"
                tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
              />
              <YAxis
                stroke="#B4C0C8"
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
                stroke="#8296A5"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorPackets)"
              />
              <Area
                type="monotone"
                dataKey="suspicious_packets"
                name="Suspicious"
                stroke="#C5A66D"
                strokeWidth={1.5}
                fillOpacity={1}
                fill="url(#colorSuspicious)"
              />
              <Area
                type="monotone"
                dataKey="threats_detected"
                name="Threats Detected"
                stroke="#C87878"
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
