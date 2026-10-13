import React, { useEffect, useRef, useState, useMemo } from 'react';
import { FileText, Terminal, Trash2, Filter, AlertTriangle, Info, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { tunnelService, createLogWebSocket } from '../services/api';
import { LogMessage, TunnelConfig } from '../types';

let logIdCounter = 0;
type LogEntry = LogMessage & { _id: number };

export const Logs: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [tunnels, setTunnels] = useState<TunnelConfig[]>([]);
  const [levelFilter, setLevelFilter] = useState('ALL');
  const [autoScroll, setAutoScroll] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let mounted = true;
    const fetchTunnels = async () => {
      try {
        const data = await tunnelService.getTunnels();
        if (mounted) setTunnels(data);
      } catch (err) {
        console.error('Failed to fetch tunnels:', err);
      }
    };
    fetchTunnels();
    const interval = setInterval(fetchTunnels, 4000);

    const cleanup = createLogWebSocket(
      (msg: LogMessage) => {
        if (mounted) {
          setLogs((prev) => [...prev.slice(-400), { ...msg, _id: ++logIdCounter }]);
        }
      },
      (err) => console.error('[HESAR] Log stream error:', err)
    );

    return () => {
      mounted = false;
      clearInterval(interval);
      cleanup();
    };
  }, []);

  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, autoScroll]);

  const filteredLogs = useMemo(
    () => logs.filter((l) => levelFilter === 'ALL' || l.level === levelFilter),
    [logs, levelFilter]
  );

  const getBadge = (level: string) => {
    if (level === 'INFO')
      return (
        <span className="flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
          <Info className="w-3 h-3 mr-1" />
          INFO
        </span>
      );
    if (level === 'WARN')
      return (
        <span className="flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <AlertTriangle className="w-3 h-3 mr-1" />
          WARN
        </span>
      );
    if (level === 'ERROR')
      return (
        <span className="flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
          <ShieldAlert className="w-3 h-3 mr-1" />
          ERROR
        </span>
      );
    return <span>{level}</span>;
  };

  return (
    <div className="space-y-8">
      <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <FileText className="w-5 h-5 text-primary-500" />
          Real-Time Tunnel Status
        </h2>
        {tunnels.length === 0 ? (
          <div className="text-xs text-slate-500 italic">No tunnels configured.</div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            {tunnels.map((t) => (
              <div
                key={t.id}
                className={
                  'p-3 rounded-xl border flex flex-col justify-between ' +
                  (t.status === 'active'
                    ? 'bg-primary-500/5 border-primary-500/20 text-primary-300'
                    : 'bg-[#0a0a0a]/40 border-[#222222] text-slate-500')
                }
              >
                <div className="font-bold text-xs truncate" title={t.name}>
                  {t.name}
                </div>
                <div className="mt-2 flex items-center justify-between text-[11px] font-semibold">
                  <span className="uppercase font-mono">{t.protocol}</span>
                  {t.status === 'active' ? (
                    <span className="flex items-center gap-1 text-primary-400">
                      <CheckCircle2 className="w-3 h-3" />
                      Live
                    </span>
                  ) : (
                    <span className="text-slate-600">Offline</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-[#0a0a0a] border border-[#222222] rounded-2xl shadow-2xl overflow-hidden flex flex-col h-[65vh]">
        <div className="bg-[#111111] px-6 py-4 border-b border-[#222222] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-2 text-sm font-semibold text-white">
            <Terminal className="w-4 h-4 text-primary-400" />
            <span>HESAR Live Console</span>
            <span className="text-xs text-slate-500 font-normal">({filteredLogs.length})</span>
          </div>
          <div className="flex items-center gap-3 ml-2">
            <div className="flex items-center space-x-1 bg-[#0a0a0a] border border-[#222222] p-1 rounded-xl text-xs font-medium">
              <Filter className="w-3.5 h-3.5 text-slate-400 ml-1.5" />
              {(['ALL', 'INFO', 'WARN', 'ERROR'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setLevelFilter(lvl)}
                  className={
                    'px-2.5 py-1 rounded-lg transition-all ' +
                    (levelFilter === lvl
                      ? 'bg-primary-500/20 text-primary-400 font-bold'
                      : 'text-slate-400 hover:text-white')
                  }
                >
                  {lvl}
                </button>
              ))}
            </div>
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={
                'px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all ' +
                (autoScroll
                  ? 'bg-primary-500/10 text-primary-400 border-primary-500/20'
                  : 'bg-[#1a1a1a] text-slate-400 border-[#222222]')
              }
            >
              {autoScroll ? 'Auto-Scroll ON' : 'Auto-Scroll OFF'}
            </button>
            <button
              onClick={() => setLogs([])}
              className="px-3 py-1.5 bg-[#1a1a1a] hover:bg-red-500/20 text-slate-400 hover:text-red-400 rounded-xl transition-colors border border-[#222222] flex items-center gap-1.5 text-xs font-semibold ml-2"
              title="Clear"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          </div>
        </div>
        <div className="p-6 font-mono text-xs overflow-y-auto flex-1 space-y-2">
          {filteredLogs.length === 0 ? (
            <div className="text-slate-600 italic text-center py-16">Listening for events...</div>
          ) : (
            filteredLogs.map((l) => (
              <div
                key={l._id}
                className="flex items-start space-x-3 hover:bg-[#111111]/50 p-1 rounded transition-colors"
              >
                <span className="text-slate-500 flex-shrink-0">{l.timestamp}</span>
                <span className="flex-shrink-0">{getBadge(l.level)}</span>
                <span
                  className={
                    'flex-1 font-medium break-all ' +
                    (l.level === 'ERROR'
                      ? 'text-red-300'
                      : l.level === 'WARN'
                      ? 'text-amber-200'
                      : 'text-slate-200')
                  }
                >
                  {l.message}
                </span>
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
};