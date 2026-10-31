import React from 'react';
import {
  DownloadCloud,
  FileSearch,
  Filter,
  Cpu,
  AlertTriangle,
  Shield,
  Database,
  ArrowRight,
  CheckCircle2,
  Clock
} from 'lucide-react';

const STAGES = [
  {
    id: 'ingest',
    number: 1,
    name: 'Packet Ingest',
    sub: 'Promiscuous NIC / Synthetic Generator',
    icon: DownloadCloud,
    color: 'text-sky-600',
    border: 'border-sky-300',
    bg: 'bg-sky-50',
  },
  {
    id: 'metadata',
    number: 2,
    name: 'Metadata Extraction',
    sub: '5-Tuple, TCP Flags, Wire Length',
    icon: FileSearch,
    color: 'text-indigo-600',
    border: 'border-indigo-300',
    bg: 'bg-indigo-50',
  },
  {
    id: 'heuristics',
    number: 3,
    name: 'Detection Engine',
    sub: 'Sliding-Window Stateful Rules',
    icon: Filter,
    color: 'text-teal-600',
    border: 'border-teal-300',
    bg: 'bg-teal-50',
  },
  {
    id: 'ml_inference',
    number: 4,
    name: 'Random Forest ML',
    sub: '76 Features, 100 Decision Trees',
    icon: Cpu,
    color: 'text-purple-600',
    border: 'border-purple-300',
    bg: 'bg-purple-50',
  },
  {
    id: 'alert',
    number: 5,
    name: 'Alert Generation',
    sub: 'Severity & Threat Reason Attribution',
    icon: AlertTriangle,
    color: 'text-amber-600',
    border: 'border-amber-300',
    bg: 'bg-amber-50',
  },
  {
    id: 'response',
    number: 6,
    name: 'Response Decision',
    sub: 'Dry-Run Containment / IP Drop',
    icon: Shield,
    color: 'text-rose-600',
    border: 'border-rose-300',
    bg: 'bg-rose-50',
  },
  {
    id: 'database',
    number: 7,
    name: 'DB & Telemetry Sync',
    sub: 'SQLite WAL & Live WebSocket Stream',
    icon: Database,
    color: 'text-emerald-600',
    border: 'border-emerald-300',
    bg: 'bg-emerald-50',
  },
];

const PacketPipeline = ({ currentStage = 'heuristics', latestEvent = null }) => {
  // Determine active stage number from stage string or latest packet/threat
  const getActiveNumber = () => {
    if (!latestEvent) return 3;
    if (latestEvent.blocked || latestEvent.status === 'blocked') return 6;
    if (latestEvent.is_threat || latestEvent.status === 'threat') return 5;
    if (latestEvent.status === 'suspicious') return 4;
    return 2;
  };

  const activeNum = getActiveNumber();

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
        <div>
          <h3 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-ping" />
            End-to-End Packet Processing Pipeline
          </h3>
          <p className="text-xs text-slate-500">
            Real-time multi-stage path from raw frame capture to Random Forest scoring and barrier defense.
          </p>
        </div>

        <span className="text-xs text-slate-500 font-mono bg-slate-50 px-2.5 py-1 rounded border border-slate-200">
          Active Stage: <strong className="text-indigo-600">Stage {activeNum}/7</strong>
        </span>
      </div>

      {/* 7 Stage Flow Grid / Flex */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
        {STAGES.map((st, idx) => {
          const Icon = st.icon;
          const isActive = st.number === activeNum;
          const isPassed = st.number < activeNum;

          return (
            <div
              key={st.id}
              className={`relative flex flex-col p-2.5 rounded-lg border transition-all duration-200 ${
                isActive
                  ? `${st.bg} ${st.border} shadow-sm ring-2 ring-indigo-400 ring-offset-1`
                  : isPassed
                  ? 'bg-slate-50/80 border-slate-200 text-slate-600'
                  : 'bg-white border-slate-100 text-slate-400 opacity-80'
              }`}
            >
              {/* Stage Number & Icon */}
              <div className="flex items-center justify-between mb-1.5">
                <span
                  className={`w-5 h-5 rounded-full text-[11px] font-bold flex items-center justify-center ${
                    isActive
                      ? 'bg-indigo-600 text-white'
                      : isPassed
                      ? 'bg-slate-200 text-slate-700'
                      : 'bg-slate-100 text-slate-400'
                  }`}
                >
                  {isPassed ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : st.number}
                </span>

                <Icon className={`w-4 h-4 ${st.color}`} />
              </div>

              {/* Title & Description */}
              <span className="text-xs font-semibold text-slate-800 leading-tight">
                {st.name}
              </span>
              <span className="text-[10px] text-slate-500 mt-0.5 leading-tight">
                {st.sub}
              </span>

              {/* Connecting arrow for larger screens */}
              {idx < STAGES.length - 1 && (
                <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-10 text-slate-300">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default PacketPipeline;

