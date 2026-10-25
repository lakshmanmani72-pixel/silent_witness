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

  const PROTO_COLORS = ['#43D6C5', '#5B8DEF', '#F5BD61', '#43D6A5', '#FF7185'];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#F3F6FC] font-mono-code flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-[#43D6C5]" />
            Security & Traffic Analytics
          </h1>
          <p className="text-xs text-[#B8C5D8] mt-1">
            Aggregated telemetry metrics, historical threat spikes, and protocol layer telemetry.
          </p>
        </div>

        {/* Time-range filter pills */}
        <div className="flex items-center gap-1 bg-[#1E2F46] border border-[#364D6E]/60 p-1 rounded-xl text-xs font-mono-code shadow-neumorph-inset">
          {[
            { label: 'Last 1 Hour', value: '1h' },
            { label: 'Last 24 Hours', value: '24h' },
            { label: 'Last 7 Days', value: '7d' },
          ].map((item) => (
            <button
              key={item.value}
              onClick={() => setTimeRange(item.value)}
              className={`px-3 py-1.5 rounded-lg transition-all text-xs font-semibold ${
                timeRange === item.value
                  ? 'bg-[#5B8DEF] text-[#F3F6FC] shadow-[0_0_12px_rgba(91,141,239,0.35)]'
                  : 'text-[#B8C5D8] hover:text-[#F3F6FC] hover:bg-[#253750]'
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
        <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#5B8DEF] to-[#43D6C5] opacity-60" />
          <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2 mb-4">
            <span className="w-2 h-2 rounded-full bg-[#43D6C5] shadow-[0_0_8px_#43D6C5]" />
            Packet Throughput Over Time
          </h3>
          <div className="h-64">
            {trafficSeries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#B8C5D8] font-mono-code">
                No telemetry recorded for this timeframe
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficSeries}>
                  <defs>
                    <linearGradient id="anPackets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#5B8DEF" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#5B8DEF" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(91, 141, 239, 0.10)" vertical={false} />
                  <XAxis dataKey="timestamp" stroke="#364D6E" tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#364D6E" tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1E2F46', borderColor: 'rgba(91, 141, 239, 0.3)', borderRadius: '12px', fontSize: '12px', fontFamily: 'monospace', color: '#F3F6FC' }}
                  />
                  <Area type="monotone" dataKey="packets_observed" name="Packets" stroke="#5B8DEF" strokeWidth={2} fill="url(#anPackets)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Threats over time */}
        <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#FF7185] to-[#F5BD61] opacity-60" />
          <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2 mb-4">
            <span className="w-2 h-2 rounded-full bg-[#FF7185] shadow-[0_0_8px_#FF7185]" />
            Detected Threat Spikes
          </h3>
          <div className="h-64">
            {trafficSeries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#B8C5D8] font-mono-code">
                No threat spikes recorded
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficSeries}>
                  <defs>
                    <linearGradient id="anThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF7185" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#FF7185" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(91, 141, 239, 0.10)" vertical={false} />
                  <XAxis dataKey="timestamp" stroke="#364D6E" tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#364D6E" tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1E2F46', borderColor: 'rgba(255, 113, 133, 0.3)', borderRadius: '12px', fontSize: '12px', fontFamily: 'monospace', color: '#F3F6FC' }}
                  />
                  <Area type="monotone" dataKey="threats_detected" name="Threat Events" stroke="#FF7185" strokeWidth={2} fill="url(#anThreats)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Row 2: Top Observed Attack Sources & Most Targeted Destination Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Source IPs Table */}
        <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#F5BD61] to-[#FF7185] opacity-60" />
          <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-[#F5BD61]" />
            Top Adversary Source IPs
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono-code">
              <thead>
                <tr className="border-b border-[#364D6E]/60 text-[#B8C5D8] uppercase text-[11px] pb-2">
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Detections</th>
                  <th className="pb-2">Highest Tier</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#364D6E]/30">
                {topSources.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="py-8 text-center text-[#B8C5D8]">No adversary sources recorded</td>
                  </tr>
                ) : (
                  topSources.map((item, idx) => (
                    <tr key={idx} className="hover:bg-[#253750]/60 transition-colors">
                      <td className="py-2.5 font-bold text-[#43D6C5]">{item.src_ip}</td>
                      <td className="py-2.5 text-[#F3F6FC] font-bold">{item.count}</td>
                      <td className="py-2.5">
                        <SeverityBadge severity={item.highest_severity} />
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => navigate(`/intelligence?ip=${item.src_ip}`)}
                          className="px-2.5 py-1 rounded-lg bg-[#253750] hover:bg-[#5B8DEF] hover:text-[#F3F6FC] border border-[#364D6E]/60 text-[#F3F6FC] transition-all text-[11px] shadow-neumorph-sm"
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
        <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#5B8DEF] to-[#B3A0FF] opacity-60" />
          <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-[#5B8DEF]" />
            Most Targeted Destination Ports
          </h3>
          <div className="h-64">
            {topPorts.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#B8C5D8] font-mono-code">
                No targeted ports data available
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPorts} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(91, 141, 239, 0.10)" vertical={false} />
                  <XAxis dataKey="dst_port" stroke="#364D6E" tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#364D6E" tick={{ fill: '#B8C5D8', fontSize: 10, fontFamily: 'monospace' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1E2F46', borderColor: 'rgba(91, 141, 239, 0.3)', borderRadius: '12px', fontSize: '12px', fontFamily: 'monospace', color: '#F3F6FC' }}
                  />
                  <Bar dataKey="count" name="Attack Probes" fill="#5B8DEF" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Row 3: Protocol Distribution Bento Grid */}
      <div className="bg-[#2B3F59]/80 backdrop-blur-md border border-[#364D6E]/70 rounded-xl p-5 shadow-aurora-card relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#43D6C5] via-[#5B8DEF] to-[#B3A0FF] opacity-60" />
        <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-[#F3F6FC] font-mono-code flex items-center gap-2 mb-4">
          <Layers className="w-4 h-4 text-[#43D6C5]" />
          Network Protocol Layer Distribution
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          {protocols.map((p, idx) => (
            <div key={idx} className="bg-[#1E2F46] border border-[#364D6E]/50 rounded-xl p-4 font-mono-code space-y-1 shadow-neumorph-inset">
              <span className="text-[11px] text-[#B8C5D8] uppercase">{p.protocol} Traffic</span>
              <p className="text-2xl font-bold text-[#43D6C5]">{p.count}</p>
              <p className="text-[10px] text-[#B8C5D8]/70">Flagged header instances</p>
            </div>
          ))}
          {protocols.length === 0 && (
            <div className="col-span-4 py-8 text-center text-xs text-[#B8C5D8] font-mono-code">
              Awaiting protocol telemetry metadata
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Analytics;
