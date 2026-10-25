import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

const THREAT_COLORS = {
  SYN_FLOOD: '#FF7185', // Aurora Coral Red
  PORT_SCAN: '#F5BD61', // Aurora Warm Amber
  SUSPICIOUS: '#5B8DEF', // Aurora Blue
  OTHER: '#43D6C5',      // Aurora Teal
};

const SEVERITY_COLORS = {
  CRITICAL: '#FF7185',
  HIGH: '#F5BD61',
  MEDIUM: '#5B8DEF',
  LOW: '#43D6A5',
  INFO: '#43D6C5',
};

export const ThreatDonutChart = ({ data = [] }) => {
  const chartData = data.length > 0 ? data : [
    { threat_type: 'No Threats', count: 1 }
  ];

  return (
    <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card flex flex-col justify-between relative overflow-hidden">
      {/* Top subtle aurora gradient line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#F5BD61] to-[#FF7185] opacity-60" />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-white/20 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-white/20 pointer-events-none" />

      <div>
        <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#F5BD61] shadow-[0_0_8px_#F5BD61]" />
          Threat Vector Distribution
        </h3>
        <p className="text-xs text-[#B8C5D8] mt-0.5">
          Breakdown by detected attack vectors
        </p>
      </div>

      <div className="h-56 w-full my-auto">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="count"
              nameKey="threat_type"
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              paddingAngle={4}
              stroke="#18263B"
              strokeWidth={2}
            >
              {chartData.map((entry, index) => {
                const color = THREAT_COLORS[entry.threat_type] || '#5B8DEF';
                return <Cell key={`cell-${index}`} fill={color} />;
              })}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-[#1E2F46]/95 border border-[#5B8DEF]/30 p-2.5 rounded-xl shadow-xl text-xs font-mono-code">
                      <p className="text-[#F3F6FC] font-bold">{payload[0].name}</p>
                      <p className="text-[#43D6C5]">Count: {payload[0].value}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Legend list */}
      <div className="flex flex-wrap items-center justify-center gap-3 pt-3 border-t border-white/[0.06] text-xs font-mono-code">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: THREAT_COLORS[item.threat_type] || '#5B8DEF' }}
            />
            <span className="text-[#B8C5D8] text-[11px]">{item.threat_type}:</span>
            <span className="font-bold text-[#F3F6FC]">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export const SeverityBarChart = ({ data = [] }) => {
  return (
    <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card flex flex-col justify-between relative overflow-hidden">
      {/* Top subtle aurora gradient line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#FF7185] to-[#B3A0FF] opacity-60" />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-white/20 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-white/20 pointer-events-none" />

      <div>
        <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#FF7185] shadow-[0_0_8px_#FF7185]" />
          Severity Classification
        </h3>
        <p className="text-xs text-[#B8C5D8] mt-0.5">
          Threat events categorized by triage tier
        </p>
      </div>

      <div className="h-56 w-full my-auto">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 20, right: 10, left: -25, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(91, 141, 239, 0.10)" vertical={false} />
            <XAxis
              dataKey="severity"
              stroke="#364D6E"
              tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
            />
            <YAxis
              stroke="#364D6E"
              tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-[#1E2F46]/95 border border-[#5B8DEF]/30 p-2.5 rounded-xl shadow-xl text-xs font-mono-code">
                      <p className="text-[#F3F6FC] font-bold">{payload[0].payload.severity}</p>
                      <p className="text-[#43D6C5]">Events: {payload[0].value}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => {
                const color = SEVERITY_COLORS[entry.severity] || '#5B8DEF';
                return <Cell key={`bar-${index}`} fill={color} />;
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Legend list */}
      <div className="flex flex-wrap items-center justify-center gap-3 pt-3 border-t border-white/[0.06] text-xs font-mono-code">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[item.severity] || '#5B8DEF' }}
            />
            <span className="text-[#B8C5D8] text-[11px]">{item.severity}:</span>
            <span className="font-bold text-[#F3F6FC]">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
