import React, { useEffect, useState } from 'react';
import {
  Activity,
  Cpu,
  HardDrive,
  ArrowDown,
  ArrowUp,
  Zap,
  Server,
  Shield,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { statsService, tunnelService } from '../services/api';
import { SystemStats, TunnelConfig } from '../types';

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [tunnels, setTunnels] = useState<TunnelConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [optimizing, setOptimizing] = useState(false);
  const [optimizeStatus, setOptimizeStatus] = useState<{
    type: 'success' | 'warning' | 'error';
    message: string;
    warnings?: string[];
  } | null>(null);

  useEffect(() => {
    let mounted = true;
    const fetchData = async () => {
      try {
        const [statsData, tunnelsData] = await Promise.all([
          statsService.getStats(),
          tunnelService.getTunnels(),
        ]);
        if (mounted) {
          setStats(statsData);
          setTunnels(tunnelsData);
        }
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleOptimize = async () => {
    setOptimizing(true);
    setOptimizeStatus(null);
    try {
      const res = await statsService.optimize();
      setOptimizeStatus({
        type: res.warnings && res.warnings.length > 0 ? 'warning' : 'success',
        message: res.message || 'Kernel BBR and socket buffers tuned.',
        warnings: res.warnings,
      });
    } catch (err) {
      setOptimizeStatus({
        type: 'error',
        message:
          err instanceof Error
            ? err.message
            : 'Failed to apply network optimizations.',
      });
    } finally {
      setOptimizing(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="w-8 h-8 rounded-full border-2 border-primary-500 border-t-transparent animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-[#111111] via-[#1a1a1a] to-[#111111] border border-[#222222] rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-64 h-64 bg-primary-500/5 rounded-full blur-3xl -mr-16 -mt-16 pointer-events-none" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-primary-500/10 border border-primary-500/20 rounded-xl text-primary-400">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">
                System Status &amp; Telemetry
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Real-time monitoring of HESAR reverse tunnels, managed carriers,
                and host resources.
              </p>
            </div>
          </div>
          <button
            onClick={handleOptimize}
            disabled={optimizing}
            className="px-4 py-2.5 bg-primary-500/15 hover:bg-primary-500/25 border border-primary-500/30 text-primary-300 font-semibold rounded-xl text-xs sm:text-sm transition-all flex items-center gap-2 self-start sm:self-auto disabled:opacity-50"
          >
            <Zap className="w-4 h-4 text-primary-400" />
            {optimizing ? 'Applying BBR & Tuning...' : 'Optimize Server & TCP BBR'}
          </button>
        </div>

        {optimizeStatus && (
          <div
            className={`mt-4 px-4 py-3 rounded-xl border text-xs flex flex-col gap-1 ${
              optimizeStatus.type === 'success'
                ? 'bg-primary-500/10 border-primary-500/20 text-primary-300'
                : optimizeStatus.type === 'warning'
                  ? 'bg-amber-500/10 border-amber-500/20 text-amber-300'
                  : 'bg-red-500/10 border-red-500/20 text-red-400'
            }`}
          >
            <div className="flex items-center gap-2 font-semibold">
              {optimizeStatus.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-primary-400" />
              ) : (
                <AlertTriangle className="w-4 h-4" />
              )}
              <span>{optimizeStatus.message}</span>
            </div>
            {optimizeStatus.warnings && optimizeStatus.warnings.length > 0 && (
              <ul className="list-disc list-inside text-[11px] opacity-90 pl-5">
                {optimizeStatus.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-[#111111]/60 backdrop-blur-md border border-[#222222] rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              CPU Usage
            </span>
            <div className="p-2 bg-[#1a1a1a] rounded-lg text-primary-400">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline space-x-2">
            <span className="text-3xl font-bold text-white">
              {stats?.cpu_usage?.toFixed(1) || '0.0'}%
            </span>
          </div>
          <div className="mt-4 w-full bg-[#1a1a1a] rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-primary-500 h-1.5 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(stats?.cpu_usage || 0, 100)}%` }}
            />
          </div>
        </div>

        <div className="bg-[#111111]/60 backdrop-blur-md border border-[#222222] rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Memory Usage
            </span>
            <div className="p-2 bg-[#1a1a1a] rounded-lg text-blue-400">
              <HardDrive className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-white">
              {stats?.memory_usage?.toFixed(1) || '0.0'}%
            </span>
            <span className="text-xs text-slate-500 font-mono">
              {formatBytes(stats?.memory_used || 0)} /{' '}
              {formatBytes(stats?.memory_total || 0)}
            </span>
          </div>
          <div className="mt-4 w-full bg-[#1a1a1a] rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-blue-500 h-1.5 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(stats?.memory_usage || 0, 100)}%` }}
            />
          </div>
        </div>

        <div className="bg-[#111111]/60 backdrop-blur-md border border-[#222222] rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Total Network Traffic
            </span>
            <div className="p-2 bg-[#1a1a1a] rounded-lg text-purple-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2">
            <div>
              <div className="flex items-center text-xs text-slate-400 mb-1">
                <ArrowDown className="w-3 h-3 text-primary-400 mr-1" /> RX (In)
              </div>
              <span className="text-lg font-bold text-white font-mono">
                {formatBytes(stats?.net_rx_bytes || 0)}
              </span>
            </div>
            <div>
              <div className="flex items-center text-xs text-slate-400 mb-1">
                <ArrowUp className="w-3 h-3 text-blue-400 mr-1" /> TX (Out)
              </div>
              <span className="text-lg font-bold text-white font-mono">
                {formatBytes(stats?.net_tx_bytes || 0)}
              </span>
            </div>
          </div>
        </div>

        <div className="bg-[#111111]/60 backdrop-blur-md border border-[#222222] rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Active Tunnels
            </span>
            <div className="p-2 bg-[#1a1a1a] rounded-lg text-primary-400">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline space-x-2">
            <span className="text-3xl font-bold text-white">
              {stats?.active_tunnels || 0}
            </span>
            <span className="text-sm text-slate-400">
              / {tunnels.length} Configured
            </span>
          </div>
          <div className="mt-4 flex items-center text-xs text-primary-400">
            <span className="w-2 h-2 rounded-full bg-primary-500 animate-ping mr-2" />
            All active listeners healthy
          </div>
        </div>
      </div>

      {/* Active Tunnels Table */}
      <div className="bg-[#111111]/60 backdrop-blur-md border border-[#222222] rounded-2xl overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-[#222222] flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center">
            <Server className="w-4 h-4 mr-2 text-primary-400" />
            Active Tunnel Connections
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#222222]/60 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-[#0a0a0a]/40">
                <th className="py-3.5 px-6">Name</th>
                <th className="py-3.5 px-6">Role</th>
                <th className="py-3.5 px-6">Transport</th>
                <th className="py-3.5 px-6">Configuration</th>
                <th className="py-3.5 px-6">Traffic (In / Out)</th>
                <th className="py-3.5 px-6">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40 text-sm">
              {tunnels.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No tunnels configured yet. Head over to the Tunnels tab to
                    create one.
                  </td>
                </tr>
              ) : (
                tunnels.map((t) => (
                  <tr
                    key={t.id}
                    className="hover:bg-[#1a1a1a]/20 transition-colors"
                  >
                    <td className="py-4 px-6 font-medium text-white">
                      {t.name}
                    </td>
                    <td className="py-4 px-6">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${
                          t.mode === 'iran'
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                            : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                        }`}
                      >
                        {t.mode === 'iran'
                          ? 'Iran (Bridge)'
                          : 'Overseas (Node)'}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-mono uppercase bg-[#1a1a1a] text-slate-300 border border-[#222222]">
                        {t.carrier && t.carrier !== 'direct'
                          ? `${t.carrier}+${t.protocol}`
                          : t.protocol}
                      </span>
                    </td>
                    <td className="py-4 px-6 font-mono text-xs text-slate-400">
                      {t.mode === 'iran'
                        ? `Listen: ${t.local_ports} -> ${t.carrier_peer_ip || t.remote_ip}:${t.carrier_port || t.remote_port}`
                        : `Listen: :${t.carrier_port || t.remote_port} -> ${t.target_host || '127.0.0.1'}:${t.target_port}`}
                    </td>
                    <td className="py-4 px-6 font-mono text-xs text-slate-300">
                      <span className="text-primary-400">
                        ↓ {formatBytes(t.bytes_in || 0)}
                      </span>
                      {' / '}
                      <span className="text-blue-400">
                        ↑ {formatBytes(t.bytes_out || 0)}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span
                        className={`inline-flex items-center text-xs font-medium ${
                          t.status === 'active'
                            ? 'text-primary-400'
                            : 'text-slate-500'
                        }`}
                      >
                        <span
                          className={`w-2 h-2 rounded-full mr-2 ${
                            t.status === 'active'
                              ? 'bg-primary-500'
                              : 'bg-slate-600'
                          }`}
                        />
                        {t.status === 'active' ? 'Running' : 'Stopped'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
