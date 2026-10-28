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
    <aside className="w-64 bg-forest border-r border-forest flex flex-col justify-between shrink-0 h-screen sticky top-0 z-30 select-none">
      {/* Top Branding */}
      <div>
        <div className="p-5 border-b border-white/15 flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-white/15 border border-white/25 text-white">
            <ShieldAlert className="w-5 h-5 text-white" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-sage border-2 border-forest" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-white flex items-center gap-1 font-mono-code">
              SILENT<span className="text-sage">WITNESS</span>
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-white/75 font-mono-code">
              Network Defense SOC
            </p>
          </div>
        </div>

        {/* Navigation links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-colors duration-150 relative group focus-visible:outline-white ${
                    isActive
                      ? 'bg-white text-forest font-semibold shadow-soft'
                      : 'text-white/85 hover:text-white hover:bg-white/10'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon className={`w-4 h-4 ${isActive ? 'text-forest' : 'text-white/80'}`} />
                    <span className="tracking-wide">{item.name}</span>
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Panel */}
      <div className="p-4 bg-white/10 border border-white/20 space-y-3 font-mono-code text-xs m-3 rounded-xl">
        {/* Connection status */}
        <div className="flex items-center justify-between">
          <span className="text-white/80 flex items-center gap-1.5 text-[11px]">
            {isConnected ? (
              <Wifi className="w-3.5 h-3.5 text-white" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 text-[#F2C2C2]" />
            )}
            Engine Link:
          </span>
          <span className={`text-[11px] font-bold ${isConnected ? 'text-white' : 'text-[#F2C2C2]'}`}>
            {isConnected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {/* Monitoring mode badge */}
        <div className="flex items-center justify-between pt-1 border-t border-white/15">
          <span className="text-white/80 text-[11px]">Mode:</span>
          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-white/90 text-forest">
            {mode === 'live' ? 'LIVE MONITOR' : 'DEMO SIMULATION'}
          </span>
        </div>

        {/* Status notice */}
        <div className="text-[10px] text-white/70 text-center leading-tight pt-1">
          Academic Project &bull; Safe Dry-Run
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
