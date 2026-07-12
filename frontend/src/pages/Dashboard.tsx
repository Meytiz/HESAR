import React, { useEffect, useState } from 'react';
import {
  Activity,
  ShieldAlert,
  CheckCircle2,
  Server,
  Cpu,
  HardDrive,
  RefreshCw,
  Zap,
} from 'lucide-react';
import { statsService } from '../services/api';
import { SystemStats } from '../types';

const formatUptime = (seconds?: number): string => {
  if (!seconds || seconds < 0) return '0h 0m 0s';
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hrs = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  if (days > 0) return days + 'd ' + hrs + 'h ' + mins + 'm';
  if (hrs > 0) return hrs + 'h ' + mins + 'm ' + secs + 's';
  return mins + 'm ' + secs + 's';
};

const formatBytes = (bytes?: number): string => {
  if (!bytes || bytes === 0) return '0 B';
  const gb = bytes / (1024 * 1024 * 1024);
  if (gb >= 1) return gb.toFixed(2) + ' GB';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return mb.toFixed(1) + ' MB';
  return (bytes / 1024).toFixed(1) + ' KB';
};

const clampPercent = (value?: number): number =>
  Math.min(Math.max(value || 0, 0), 100);

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const fetchData = async () => {
      try {
        const data = await statsService.getStats();
        if (mounted) setStats(data);
      } catch (err) {
        console.error('Failed to fetch stats:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
          <p className="text-sm text-slate-500">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
        <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Total Tunnels</span>
            <div className="p-2 bg-[#1a1a1a]/80 rounded-xl">
              <Server className="w-5 h-5 text-primary-400" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <div className="text-3xl font-extrabold text-white">
              {stats ? stats.total_tunnels : 0}
            </div>
            <span className="text-xs text-slate-500 font-mono">Configured</span>
          </div>
          <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-primary-500/5 rounded-full blur-xl pointer-events-none" />
        </div>

        <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Active Tunnels</span>
            <div className="p-2 bg-primary-500/10 border border-primary-500/20 rounded-xl">
              <CheckCircle2 className="w-5 h-5 text-primary-400" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <div className="text-3xl font-extrabold text-primary-400">
              {stats ? stats.active_tunnels : 0}
            </div>
            <span className="w-2 h-2 rounded-full bg-primary-500 animate-pulse" />
          </div>
          <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-primary-500/10 rounded-full blur-xl pointer-events-none" />
        </div>

        <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-5 shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Inactive</span>
            <div className="p-2 bg-red-500/10 border border-red-500/20 rounded-xl">
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
          </div>
          <div className="mt-4 text-3xl font-extrabold text-red-400">
            {stats ? stats.inactive_tunnels : 0}
          </div>
          <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-red-500/10 rounded-full blur-xl pointer-events-none" />
        </div>
      </div>

      <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
        <h2 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary-500" />
          Server Resources
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-sm text-slate-400 mb-2">
              <span>CPU</span>
              <Cpu className="w-4 h-4 text-primary-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">
                {(stats ? stats.cpu_usage : 0).toFixed(1)}%
              </div>
              <div className="w-full bg-[#1a1a1a] h-2 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-primary-500 h-full rounded-full transition-all duration-500"
                  style={{ width: clampPercent(stats ? stats.cpu_usage : 0) + '%' }}
                />
              </div>
            </div>
          </div>

          <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-sm text-slate-400 mb-2">
              <span>Memory</span>
              <HardDrive className="w-4 h-4 text-primary-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">
                {(stats ? stats.memory_usage : 0).toFixed(1)}%
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {formatBytes(stats ? stats.memory_used : 0)} / {formatBytes(stats ? stats.memory_total : 0)}
              </div>
              <div className="w-full bg-[#1a1a1a] h-2 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-primary-500 h-full rounded-full transition-all duration-500"
                  style={{ width: clampPercent(stats ? stats.memory_usage : 0) + '%' }}
                />
              </div>
            </div>
          </div>

          <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-sm text-slate-400 mb-2">
              <span>Load (1m)</span>
              <Activity className="w-4 h-4 text-primary-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {(stats ? stats.load_avg_1 : 0).toFixed(2)}
            </div>
            <div className="text-xs text-slate-500 mt-1 flex items-center gap-1.5">
              <span>BBR:</span>
              {stats && stats.bbr_active ? (
                <span className="text-primary-400 font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-primary-500 inline-block" />
                  Active
                </span>
              ) : (
                <span className="text-slate-500 font-semibold">Disabled</span>
              )}
            </div>
          </div>

          <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-sm text-slate-400 mb-2">
              <span>Uptime</span>
              <Zap className="w-4 h-4 text-primary-400" />
            </div>
            <div className="text-xl font-bold text-white font-mono">
              {formatUptime(stats ? stats.panel_uptime : 0)}
            </div>
            <div className="text-xs text-slate-500 mt-1">HESAR Core</div>
          </div>
        </div>
      </div>
    </div>
  );
};