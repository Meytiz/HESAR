import React, { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  Save,
  CheckCircle2,
  User,
  Key,
  Folder,
  Database,
  RefreshCw,
  Cpu,
  HardDrive,
  AlertTriangle,
  Globe,
} from 'lucide-react';
import { configService, statsService } from '../services/api';
import { SystemStats } from '../types';

const getErrorMessage = (err: unknown, fallback: string): string => {
  if (err && typeof err === 'object' && 'response' in err) {
    const axiosErr = err as { response?: { data?: unknown } };
    const data = axiosErr.response?.data;
    if (typeof data === 'string') return data;
    if (data && typeof data === 'object') {
      const obj = data as Record<string, unknown>;
      if (typeof obj.error === 'string') return obj.error;
      if (typeof obj.message === 'string') return obj.message;
    }
  }
  if (err instanceof Error) return err.message;
  return fallback;
};

const formatBytes = (bytes?: number): string => {
  if (!bytes || bytes === 0) return '0 B';
  const gb = bytes / (1024 * 1024 * 1024);
  if (gb >= 1) return `${gb.toFixed(2)} GB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const Settings: React.FC = () => {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [logPath, setLogPath] = useState('');
  const [logMaxSize, setLogMaxSize] = useState(10);
  const [allowedOriginsText, setAllowedOriginsText] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [configData, statsData] = await Promise.all([
          configService.getConfig(),
          statsService.getStats(),
        ]);
        setStats(statsData);
        setUsername(configData.admin_username);
        setLogPath(configData.log_path);
        setLogMaxSize(configData.log_max_size_mb);
        setAllowedOriginsText((configData.allowed_origins || []).join(', '));
      } catch (err) {
        console.error('Failed to fetch settings data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSuccessMsg(null);
    setErrorMsg(null);

    if (password && password !== passwordConfirm) {
      setErrorMsg('Passwords do not match.');
      return;
    }
    if (password && password.length < 8) {
      setErrorMsg('Password must be at least 8 characters.');
      return;
    }

    const allowedOrigins = allowedOriginsText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    setSaving(true);
    try {
      await configService.updateConfig({
        admin_username: username,
        admin_password: password || undefined,
        log_path: logPath,
        log_max_size_mb: Number(logMaxSize),
        allowed_origins: allowedOrigins,
      });

      setSuccessMsg('Settings updated successfully!');
      setPassword('');
      setPasswordConfirm('');
    } catch (err) {
      setErrorMsg(getErrorMessage(err, 'Failed to update settings'));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <SettingsIcon className="w-6 h-6 text-primary-500" />
          System Configuration &amp; Information
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Manage your Panel login credentials, Log storage location, WebSocket
          origin allowlist, and view server properties.
        </p>
      </div>

      {successMsg && (
        <div className="bg-primary-500/10 border border-primary-500/20 text-primary-400 px-4 py-3 rounded-xl flex items-center gap-2 text-sm">
          <CheckCircle2 className="w-5 h-5 text-primary-500 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}
      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-xl flex items-center gap-2 text-sm">
          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
          <h2 className="text-lg font-bold text-white mb-6 border-b border-[#222222] pb-3">
            GUI Credential Controls &amp; Log Paths
          </h2>

          <form onSubmit={handleSubmit} className="space-y-5">
            <fieldset disabled={saving}>
              <div className="space-y-5">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <User className="w-4 h-4 text-primary-400" /> GUI Login
                    Admin Username
                  </label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-semibold"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <Key className="w-4 h-4 text-primary-400" /> New Admin
                    Password
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Leave empty to keep existing password"
                    autoComplete="new-password"
                    className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                  />
                </div>

                {password && (
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                      <Key className="w-4 h-4 text-primary-400" /> Confirm New
                      Password
                    </label>
                    <input
                      type="password"
                      value={passwordConfirm}
                      onChange={(e) => setPasswordConfirm(e.target.value)}
                      placeholder="Re-enter new password"
                      autoComplete="new-password"
                      className={`w-full bg-[#0a0a0a] border rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none font-mono ${
                        passwordConfirm && password !== passwordConfirm
                          ? 'border-red-500 focus:border-red-500'
                          : 'border-[#222222] focus:border-primary-500'
                      }`}
                    />
                    {passwordConfirm && password !== passwordConfirm && (
                      <p className="text-xs text-red-400 mt-1">
                        Passwords do not match
                      </p>
                    )}
                  </div>
                )}

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <Folder className="w-4 h-4 text-primary-400" /> System Log
                    Storage Path
                  </label>
                  <input
                    type="text"
                    required
                    value={logPath}
                    onChange={(e) => setLogPath(e.target.value)}
                    placeholder="/var/log/hesar/hesar.log"
                    className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <Database className="w-4 h-4 text-primary-400" /> Log
                    Rotation Max Size (MB)
                  </label>
                  <input
                    type="number"
                    required
                    min={1}
                    max={1000}
                    value={logMaxSize}
                    onChange={(e) => setLogMaxSize(Number(e.target.value))}
                    className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <Globe className="w-4 h-4 text-primary-400" /> Allowed
                    Reverse-Proxy Origins (Optional)
                  </label>
                  <input
                    type="text"
                    value={allowedOriginsText}
                    onChange={(e) => setAllowedOriginsText(e.target.value)}
                    placeholder="https://panel.example.com"
                    className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Comma-separated origins allowed for WebSocket log streaming
                    when behind a reverse proxy.
                  </p>
                </div>
              </div>
            </fieldset>

            <div className="pt-2">
              <button
                type="submit"
                disabled={saving}
                className="w-full py-3 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-bold rounded-xl shadow-lg shadow-primary-500/20 transition-all text-sm flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {saving ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {saving ? 'Saving...' : 'Apply & Save Settings'}
              </button>
            </div>
          </form>
        </div>

        <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-bold text-white mb-6 border-b border-[#222222] pb-3 flex items-center gap-2">
              <HardDrive className="w-5 h-5 text-primary-500" />
              Hardware &amp; Operating System Summary
            </h2>

            <div className="space-y-4">
              <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-[#1a1a1a] rounded-lg text-primary-400">
                    <Cpu className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs text-slate-400 font-semibold uppercase">
                      Engine Architecture
                    </div>
                    <div className="text-sm font-bold text-white mt-0.5">
                      HESAR Core + Local Root Network Agent
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-[#1a1a1a] rounded-lg text-blue-400">
                    <Database className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs text-slate-400 font-semibold uppercase">
                      Supported Transports &amp; Carriers
                    </div>
                    <div className="text-sm font-bold text-white mt-0.5">
                      QUIC, WSS, Shaped-WSS, Auto, Paqet, Xray REALITY, Hysteria 2, GRE, IPIP
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-[#1a1a1a] rounded-lg text-purple-400">
                    <HardDrive className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs text-slate-400 font-semibold uppercase">
                      Physical System Memory
                    </div>
                    <div className="text-sm font-bold text-white mt-0.5 font-mono">
                      {formatBytes(stats?.memory_used)} /{' '}
                      {formatBytes(stats?.memory_total)} (
                      {(stats?.memory_usage ?? 0).toFixed(1)}%)
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 bg-primary-500/5 border border-primary-500/20 p-4 rounded-xl text-xs text-slate-400 leading-relaxed">
            <span className="text-primary-400 font-bold inline-block mb-1">
              Deployment Tip:
            </span>
            <br />
            Configure the Overseas node first, click{' '}
            <strong className="text-slate-200">Copy peer setup</strong> on the
            tunnel card, then use{' '}
            <strong className="text-slate-200">Import peer setup</strong> on your
            Iran panel to transfer pinned certificates, REALITY public keys, and
            carrier secrets automatically.
          </div>
        </div>
      </div>
    </div>
  );
};
