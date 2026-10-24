import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart3,
  Calendar,
  Layers,
  Shield,
  Activity,
  Server,
  Filter,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import SeverityBadge from '../components/SeverityBadge';
import { endpoints } from '../services/api';

const Analytics = () => {
  const navigate = useNavigate();
  const [timeRange, setTimeRange] = useState('24h');

  // Chart datasets
  const [trafficSeries, setTrafficSeries] = useState([]);
  const [threatsSeries, setThreatsSeries] = useState([]);
  const [topSources, setTopSources] = useState([]);
  const [topPorts, setTopPorts] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [blockedTrends, setBlockedTrends] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const [trafRes, threatRes, srcRes, portRes, protoRes, blockRes] = await Promise.all([
        endpoints.getAnalyticsTraffic(timeRange),
        endpoints.getAnalyticsThreats(timeRange),
        endpoints.getTopSources(timeRange, 8),
        endpoints.getTopPorts(timeRange, 8),
        endpoints.getProtocolDistribution(timeRange),
        endpoints.getBlockedTrends(timeRange),
      ]);

      setTrafficSeries(trafRes.data || []);
      setThreatsSeries(threatRes.data || []);
      setTopSources(srcRes.data || []);
      setTopPorts(portRes.data || []);
      setProtocols(protoRes.data || []);
      setBlockedTrends(blockRes.data || []);
    } catch (err) {
      console.error('Failed to load analytics data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, [timeRange]);

  const PROTO_COLORS = ['#00F5FF', '#3B82F6', '#FFB020', '#00FFA3', '#FF355E'];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white font-mono-code flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyber-cyan" />
            Security & Traffic Analytics
          </h1>
          <p className="text-xs text-cyber-muted mt-1">
            Aggregated metrics, historical threat trends, and network telemetry analytics.
          </p>
        </div>

        {/* Time-range filter pills */}
        <div className="flex items-center gap-1 bg-cyber-panel border border-cyber-border/40 p-1 rounded-lg text-xs font-mono-code">
          {[
            { label: 'Last 1 Hour', value: '1h' },
            { label: 'Last 24 Hours', value: '24h' },
            { label: 'Last 7 Days', value: '7d' },
          ].map((item) => (
            <button
              key={item.value}
              onClick={() => setTimeRange(item.value)}
              className={`px-3 py-1.5 rounded transition-all ${
                timeRange === item.value
                  ? 'bg-cyber-cyan text-black font-bold shadow-cyan-glow'
                  : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-card'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Row 1: Traffic & Threat Volume Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Packets over time */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2 mb-4">
            <span className="w-2 h-2 rounded-full bg-cyber-cyan" />
            Packet Throughput Over Time
          </h3>
          <div className="h-64">
            {trafficSeries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted font-mono-code">
                No telemetry recorded for this timeframe
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficSeries}>
                  <defs>
                    <linearGradient id="anPackets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00F5FF" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#00F5FF" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 245, 255, 0.07)" vertical={false} />
                  <XAxis dataKey="timestamp" stroke="#64748B" tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#64748B" tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111C31', borderColor: 'rgba(0, 245, 255, 0.3)', borderRadius: '8px', fontSize: '12px', fontFamily: 'monospace' }}
                  />
                  <Area type="monotone" dataKey="packets_observed" name="Packets" stroke="#00F5FF" fill="url(#anPackets)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Threats over time */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2 mb-4">
            <span className="w-2 h-2 rounded-full bg-cyber-red" />
            Detected Threat Spikes
          </h3>
          <div className="h-64">
            {trafficSeries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted font-mono-code">
                No threat spikes recorded
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficSeries}>
                  <defs>
                    <linearGradient id="anThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF355E" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#FF355E" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 245, 255, 0.07)" vertical={false} />
                  <XAxis dataKey="timestamp" stroke="#64748B" tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#64748B" tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111C31', borderColor: 'rgba(255, 53, 94, 0.4)', borderRadius: '8px', fontSize: '12px', fontFamily: 'monospace' }}
                  />
                  <Area type="monotone" dataKey="threats_detected" name="Threat Events" stroke="#FF355E" fill="url(#anThreats)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Row 2: Top Observed Attack Sources & Most Targeted Destination Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Source IPs Table */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-cyber-amber" />
            Top Adversary Source IPs
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono-code">
              <thead>
                <tr className="border-b border-cyber-border/40 text-cyber-muted uppercase text-[11px] pb-2">
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Detections</th>
                  <th className="pb-2">Highest Tier</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/20">
                {topSources.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="py-8 text-center text-cyber-muted">No adversary sources recorded</td>
                  </tr>
                ) : (
                  topSources.map((item, idx) => (
                    <tr key={idx} className="hover:bg-cyber-panel/50 transition-colors">
                      <td className="py-2.5 font-bold text-cyber-cyan">{item.src_ip}</td>
                      <td className="py-2.5 text-cyber-text font-bold">{item.count}</td>
                      <td className="py-2.5">
                        <SeverityBadge severity={item.highest_severity} />
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => navigate(`/intelligence?ip=${item.src_ip}`)}
                          className="px-2 py-0.5 rounded bg-cyber-panel hover:bg-cyber-cyan hover:text-black text-cyber-text transition-all text-[11px]"
                        >
                          Profile
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Most Targeted Ports Bar Chart */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-cyber-blue" />
            Most Targeted Destination Ports
          </h3>
          <div className="h-64">
            {topPorts.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted font-mono-code">
                No targeted ports data available
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPorts} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 245, 255, 0.07)" vertical={false} />
                  <XAxis dataKey="dst_port" stroke="#64748B" tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#64748B" tick={{ fill: '#64748B', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111C31', borderColor: 'rgba(59, 130, 246, 0.4)', borderRadius: '8px', fontSize: '12px', fontFamily: 'monospace' }}
                  />
                  <Bar dataKey="count" name="Attack Probes" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Row 3: Protocol Distribution */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2 mb-4">
          <Layers className="w-4 h-4 text-cyber-cyan" />
          Network Protocol Distribution
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {protocols.map((p, idx) => (
            <div key={idx} className="bg-cyber-panel/60 border border-cyber-border/40 rounded-xl p-4 font-mono-code space-y-1">
              <span className="text-xs text-cyber-muted uppercase">{p.protocol} Traffic</span>
              <p className="text-2xl font-bold text-cyber-cyan">{p.count}</p>
              <p className="text-[10px] text-cyber-muted">Flagged header instances</p>
            </div>
          ))}
          {protocols.length === 0 && (
            <div className="col-span-4 py-8 text-center text-xs text-cyber-muted font-mono-code">
              Awaiting protocol metadata
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Analytics;
