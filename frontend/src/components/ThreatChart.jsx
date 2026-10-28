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
  SYN_FLOOD: '#C87878',
  PORT_SCAN: '#C5A66D',
  SUSPICIOUS: '#8296A5',
  OTHER: '#54766A',     
};

const SEVERITY_COLORS = {
  CRITICAL: '#C87878',
  HIGH: '#C5A66D',
  MEDIUM: '#8296A5',
  LOW: '#7C9B83',
  INFO: '#54766A',
};

export const ThreatDonutChart = ({ data = [] }) => {
  const chartData = data.length > 0 ? data : [
    { threat_type: 'No Threats', count: 1 }
  ];

  return (
    <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft flex flex-col justify-between relative overflow-hidden">
      {/* Top subtle aurora gradient line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-amber to-bad opacity-60" />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-bluegrey/25 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-bluegrey/25 pointer-events-none" />

      <div>
        <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-ink font-mono-code flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber shadow-soft" />
          Threat Vector Distribution
        </h3>
        <p className="text-xs text-muted mt-0.5">
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
              stroke="#ECEFEA"
              strokeWidth={2}
            >
              {chartData.map((entry, index) => {
                const color = THREAT_COLORS[entry.threat_type] || '#8296A5';
                return <Cell key={`cell-${index}`} fill={color} />;
              })}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-sage/95 border border-bluegrey/30 p-2.5 rounded-xl shadow-xl text-xs font-mono-code">
                      <p className="text-ink font-bold">{payload[0].name}</p>
                      <p className="text-forest">Count: {payload[0].value}</p>
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
      <div className="flex flex-wrap items-center justify-center gap-3 pt-3 border-t border-bluegrey/25 text-xs font-mono-code">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: THREAT_COLORS[item.threat_type] || '#8296A5' }}
            />
            <span className="text-muted text-[11px]">{item.threat_type}:</span>
            <span className="font-bold text-ink">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export const SeverityBarChart = ({ data = [] }) => {
  return (
    <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft flex flex-col justify-between relative overflow-hidden">
      {/* Top subtle aurora gradient line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-bad to-bluegrey opacity-60" />

      {/* Blueprint technical corner markers */}
      <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-bluegrey/25 pointer-events-none" />
      <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-bluegrey/25 pointer-events-none" />

      <div>
        <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-ink font-mono-code flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-bad shadow-soft" />
          Severity Classification
        </h3>
        <p className="text-xs text-muted mt-0.5">
          Threat events categorized by triage tier
        </p>
      </div>

      <div className="h-56 w-full my-auto">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 20, right: 10, left: -25, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(130,150,165, 0.10)" vertical={false} />
            <XAxis
              dataKey="severity"
              stroke="#B4C0C8"
              tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
            />
            <YAxis
              stroke="#B4C0C8"
              tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-sage/95 border border-bluegrey/30 p-2.5 rounded-xl shadow-xl text-xs font-mono-code">
                      <p className="text-ink font-bold">{payload[0].payload.severity}</p>
                      <p className="text-forest">Events: {payload[0].value}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => {
                const color = SEVERITY_COLORS[entry.severity] || '#8296A5';
                return <Cell key={`bar-${index}`} fill={color} />;
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Legend list */}
      <div className="flex flex-wrap items-center justify-center gap-3 pt-3 border-t border-bluegrey/25 text-xs font-mono-code">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[item.severity] || '#8296A5' }}
            />
            <span className="text-muted text-[11px]">{item.severity}:</span>
            <span className="font-bold text-ink">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
