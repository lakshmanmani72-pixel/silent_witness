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
  SYN_FLOOD: '#FF355E', // Red
  PORT_SCAN: '#FFB020', // Amber
  SUSPICIOUS: '#3B82F6', // Blue
  OTHER: '#00F5FF',      // Cyan
};

const SEVERITY_COLORS = {
  CRITICAL: '#FF355E',
  HIGH: '#FFB020',
  MEDIUM: '#3B82F6',
  LOW: '#00FFA3',
  INFO: '#00F5FF',
};

export const ThreatDonutChart = ({ data = [] }) => {
  const chartData = data.length > 0 ? data : [
    { threat_type: 'No Threats', count: 1 }
  ];

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg flex flex-col justify-between">
      <div>
        <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyber-amber" />
          Threat Vector Distribution
        </h3>
        <p className="text-xs text-cyber-muted mt-0.5">
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
              stroke="#0F172A"
              strokeWidth={2}
            >
              {chartData.map((entry, index) => {
                const color = THREAT_COLORS[entry.threat_type] || '#64748B';
                return <Cell key={`cell-${index}`} fill={color} />;
              })}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-cyber-panel/95 border border-cyber-border p-2.5 rounded-lg shadow-xl text-xs font-mono-code">
                      <p className="text-cyber-text font-bold">{payload[0].name}</p>
                      <p className="text-cyber-cyan">Count: {payload[0].value}</p>
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
      <div className="flex flex-wrap items-center justify-center gap-3 pt-2 border-t border-cyber-border/30 text-xs font-mono-code">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: THREAT_COLORS[item.threat_type] || '#64748B' }}
            />
            <span className="text-cyber-muted text-[11px]">{item.threat_type}:</span>
            <span className="font-bold text-cyber-text">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export const SeverityBarChart = ({ data = [] }) => {
  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg flex flex-col justify-between">
      <div>
        <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyber-red" />
          Severity Classification
        </h3>
        <p className="text-xs text-cyber-muted mt-0.5">
          Threat events by triage severity tier
        </p>
      </div>

      <div className="h-56 w-full my-auto">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 20, right: 10, left: -25, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 245, 255, 0.07)" vertical={false} />
            <XAxis
              dataKey="severity"
              stroke="#64748B"
              tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
            />
            <YAxis
              stroke="#64748B"
              tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-cyber-panel/95 border border-cyber-border p-2.5 rounded-lg shadow-xl text-xs font-mono-code">
                      <p className="text-cyber-text font-bold">{payload[0].payload.severity}</p>
                      <p className="text-cyber-cyan">Events: {payload[0].value}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => {
                const color = SEVERITY_COLORS[entry.severity] || '#00F5FF';
                return <Cell key={`bar-${index}`} fill={color} />;
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Legend list */}
      <div className="flex flex-wrap items-center justify-center gap-3 pt-2 border-t border-cyber-border/30 text-xs font-mono-code">
        {data.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[item.severity] || '#64748B' }}
            />
            <span className="text-cyber-muted text-[11px]">{item.severity}:</span>
            <span className="font-bold text-cyber-text">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
