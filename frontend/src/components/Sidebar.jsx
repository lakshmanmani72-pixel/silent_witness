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

const Sidebar = ({ isLive, isConnected, mode = 'simulation' }) => {
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
    <aside className="w-64 bg-cyber-secondary border-r border-cyber-border flex flex-col justify-between shrink-0 h-screen sticky top-0 z-30 select-none">
      {/* Top Branding */}
      <div>
        <div className="p-5 border-b border-cyber-border/40 flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-cyan-glow">
            <ShieldAlert className="w-6 h-6 animate-pulse-subtle" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyber-cyan animate-ping" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-wider text-cyber-text flex items-center gap-1.5 font-mono-code">
              SILENT<span className="text-cyber-cyan">WITNESS</span>
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-cyber-muted font-mono-code">
              Network Defense SOC
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
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 relative group ${
                    isActive
                      ? 'bg-cyber-panel text-cyber-cyan border border-cyber-cyan/30 shadow-[0_0_15px_rgba(0,245,255,0.15)] font-semibold'
                      : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-card/60 border border-transparent'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    {/* Active left indicator pill */}
                    {isActive && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-cyber-cyan rounded-r shadow-cyan-glow" />
                    )}
                    <Icon className={`w-4 h-4 transition-transform group-hover:scale-110 ${isActive ? 'text-cyber-cyan' : 'text-cyber-muted'}`} />
                    <span>{item.name}</span>
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Panel */}
      <div className="p-4 border-t border-cyber-border/40 bg-cyber-bg/50 space-y-3 font-mono-code text-xs">
        {/* Connection status */}
        <div className="flex items-center justify-between">
          <span className="text-cyber-muted flex items-center gap-1.5">
            {isConnected ? (
              <Wifi className="w-3.5 h-3.5 text-cyber-green" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 text-cyber-red" />
            )}
            Backend:
          </span>
          <span className={`font-semibold ${isConnected ? 'text-cyber-green' : 'text-cyber-red'}`}>
            {isConnected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {/* Monitoring mode badge */}
        <div className="flex items-center justify-between pt-1 border-t border-cyber-border/20">
          <span className="text-cyber-muted">Engine Mode:</span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
            mode === 'live'
              ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30'
              : 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 shadow-[0_0_8px_rgba(0,245,255,0.2)]'
          }`}>
            {mode === 'live' ? 'LIVE MONITOR' : 'DEMO SIMULATION'}
          </span>
        </div>

        {/* Status notice */}
        <div className="text-[10px] text-cyber-muted/80 text-center leading-tight">
          Defensive Project &bull; Safe Dry-Run
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
