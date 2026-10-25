import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  Activity,
  BarChart3,
  Search,
  Ban,
  History,
  FileText,
  Settings,
  Radio,
  Wifi,
  WifiOff,
} from 'lucide-react';

const Sidebar = ({ isConnected, mode = 'simulation' }) => {
  const navItems = [
    { name: 'Overview', path: '/', icon: Activity },
    { name: 'Live Threat Monitor', path: '/threats', icon: Radio },
    { name: 'Traffic Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'Threat Intelligence', path: '/intelligence', icon: Search },
    { name: 'Blocked IPs', path: '/blocked', icon: Ban },
    { name: 'Incident History', path: '/incidents', icon: History },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'System Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#253750] border-r border-[#364D6E]/60 flex flex-col justify-between shrink-0 h-screen sticky top-0 z-30 select-none shadow-[4px_0_24px_rgba(10,18,30,0.3)]">
      {/* Top Branding */}
      <div>
        <div className="p-5 border-b border-[#364D6E]/50 flex items-center gap-3 bg-gradient-to-b from-[#2B3F59]/40 to-transparent">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-[#5B8DEF]/20 to-[#43D6C5]/20 border border-[#5B8DEF]/35 text-[#43D6C5] shadow-[0_0_15px_rgba(91,141,239,0.2)]">
            <ShieldAlert className="w-5 h-5 text-[#5B8DEF]" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#43D6C5] shadow-[0_0_8px_#43D6C5]" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-[#F3F6FC] flex items-center gap-1 font-mono-code">
              SILENT<span className="text-[#43D6C5]">WITNESS</span>
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-[#B8C5D8] font-mono-code">
              Hybrid Aurora SOC
            </p>
          </div>
        </div>

        {/* Navigation links */}
        <nav className="p-3 space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 relative group ${
                    isActive
                      ? 'bg-[#2B3F59] text-[#F3F6FC] border border-[#5B8DEF]/35 shadow-neumorph-sm font-semibold'
                      : 'text-[#B8C5D8] hover:text-[#F3F6FC] hover:bg-[#2B3F59]/50 border border-transparent'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    {/* Active left indicator pill */}
                    {isActive && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-[#43D6C5] rounded-r shadow-[0_0_8px_#43D6C5]" />
                    )}
                    <Icon className={`w-4 h-4 transition-transform group-hover:scale-105 ${isActive ? 'text-[#43D6C5]' : 'text-[#B8C5D8]'}`} />
                    <span className="tracking-wide">{item.name}</span>
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Panel */}
      <div className="p-4 border-t border-[#364D6E]/50 bg-[#1E2F46]/60 backdrop-blur-sm space-y-3 font-mono-code text-xs m-3 rounded-xl border">
        {/* Connection status */}
        <div className="flex items-center justify-between">
          <span className="text-[#B8C5D8] flex items-center gap-1.5 text-[11px]">
            {isConnected ? (
              <Wifi className="w-3.5 h-3.5 text-[#43D6A5]" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 text-[#FF7185]" />
            )}
            Engine Link:
          </span>
          <span className={`text-[11px] font-bold ${isConnected ? 'text-[#43D6A5]' : 'text-[#FF7185]'}`}>
            {isConnected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {/* Monitoring mode badge */}
        <div className="flex items-center justify-between pt-1 border-t border-[#364D6E]/40">
          <span className="text-[#B8C5D8] text-[11px]">Mode:</span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
            mode === 'live'
              ? 'bg-[#43D6A5]/15 text-[#43D6A5] border border-[#43D6A5]/30'
              : 'bg-[#5B8DEF]/15 text-[#5B8DEF] border border-[#5B8DEF]/30'
          }`}>
            {mode === 'live' ? 'LIVE MONITOR' : 'DEMO SIMULATION'}
          </span>
        </div>

        {/* Status notice */}
        <div className="text-[10px] text-[#B8C5D8]/70 text-center leading-tight pt-1">
          Academic Project &bull; Safe Dry-Run
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
