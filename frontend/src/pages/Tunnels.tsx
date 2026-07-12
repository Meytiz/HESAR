import React, { useEffect, useState, useCallback } from 'react';
import {
  HardDrive,
  Plus,
  Play,
  Square,
  Trash2,
  Edit,
  Key,
  ArrowRight,
  Activity,
  ShieldCheck,
  HelpCircle,
  X,
} from 'lucide-react';
import { toolService, tunnelService } from '../services/api';
import { TunnelConfig } from '../types';

// ──────────────────────────────────────────────────
// Helper: error message extraction
// ──────────────────────────────────────────────────

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

// ──────────────────────────────────────────────────
// Helper: format bytes
// ──────────────────────────────────────────────────

const formatBytes = (bytes?: number): string => {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

// ──────────────────────────────────────────────────
// Component
// ──────────────────────────────────────────────────

export const Tunnels: React.FC = () => {
  const [tunnels, setTunnels] = useState<TunnelConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Form State
  const [name, setName] = useState('');
  const [mode, setMode] = useState<'iran' | 'overseas'>('iran');
  const [protocol, setProtocol] = useState<
    'kcp' | 'tcp' | 'ip_spoof' | 'sni_spoof'
  >('tcp');
  const [localPorts, setLocalPorts] = useState('80');
  const [remoteIp, setRemoteIp] = useState('');
  const [remotePort, setRemotePort] = useState(443);
  const [encryptionKey, setEncryptionKey] = useState('');
  const [targetPort, setTargetPort] = useState(8080);
  const [kcpMode, setKcpMode] = useState<'normal' | 'fast' | 'fast2' | 'fast3'>('fast3');
  const [spoofSni, setSpoofSni] = useState('www.aparat.com');
  const [fakeIp, setFakeIp] = useState('185.10.20.30');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Confirm delete modal
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // ✅ Notification toast
  const [toast, setToast] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const showToast = useCallback(
    (type: 'success' | 'error', message: string) => {
      setToast({ type, message });
      setTimeout(() => setToast(null), 4000);
    },
    []
  );

  // ── Fetch tunnels ──
  useEffect(() => {
    let mounted = true;
    const fetchTunnels = async () => {
      try {
        const data = await tunnelService.getTunnels();
        if (mounted) setTunnels(data);
      } catch (err) {
        console.error('Failed to fetch tunnels:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchTunnels();
    const interval = setInterval(fetchTunnels, 3000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  // ── Modal helpers ──
  const openAddModal = () => {
    setEditingId(null);
    setName('');
    setMode('iran');
    setProtocol('tcp');
    setLocalPorts('80,880');
    setRemoteIp('');
    setRemotePort(443);
    setEncryptionKey(''); // ✅ خالی — کاربر keygen بزند
    setTargetPort(8080);
    setKcpMode('fast3');
    setSpoofSni('www.aparat.com');
    setFakeIp('185.10.20.30');
    setSaveError(null);
    setModalOpen(true);
  };

  const openEditModal = (t: TunnelConfig) => {
    setEditingId(t.id);
    setName(t.name);
    setMode(t.mode);
    setProtocol(t.protocol);
    setLocalPorts(t.local_ports);
    setRemoteIp(t.remote_ip);
    setRemotePort(t.remote_port);
    setEncryptionKey(t.encryption_key);
    setTargetPort(t.target_port || 8080);
    setKcpMode(t.kcp_mode || 'fast3');
    setSpoofSni(t.spoof_sni || 'www.aparat.com');
    setFakeIp(t.fake_ip || '185.10.20.30');
    setSaveError(null);
    setModalOpen(true);
  };

  const handleKeygen = async () => {
    try {
      const keys = await toolService.keygen();
      setEncryptionKey(keys.encryption_key);
    } catch {
      // ✅ fallback تصادفی امن
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      setEncryptionKey(
        Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
      );
    }
  };

  // ── CRUD ──
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!encryptionKey) {
      setSaveError(
        'Encryption key is required. Click "Key Generation" to create one.'
      );
      return;
    }

    setSaving(true);
    setSaveError(null);

    const payload: Partial<TunnelConfig> = {
      id: editingId || undefined,
      name: name || `Tunnel_${protocol.toUpperCase()}_${remotePort}`,
      mode,
      protocol,
      local_ports: mode === 'iran' ? localPorts : '',
      remote_ip: mode === 'iran' ? remoteIp : '',
      remote_port: Number(remotePort),
      encryption_key: encryptionKey,
      target_port: Number(targetPort),
      kcp_mode: kcpMode,
      spoof_sni: spoofSni,
      fake_ip: fakeIp,
    };

    try {
      await tunnelService.saveTunnel(payload);
      setModalOpen(false);
      showToast('success', `Tunnel "${payload.name}" saved successfully.`);
      // refresh
      const data = await tunnelService.getTunnels();
      setTunnels(data);
    } catch (err) {
      setSaveError(getErrorMessage(err, 'Failed to save tunnel configuration'));
    } finally {
      setSaving(false);
    }
  };

  const handleStart = async (id: string) => {
    try {
      await tunnelService.startTunnel(id);
      showToast('success', 'Tunnel started.');
      const data = await tunnelService.getTunnels();
      setTunnels(data);
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to start tunnel'));
    }
  };

  const handleStop = async (id: string) => {
    try {
      await tunnelService.stopTunnel(id);
      showToast('success', 'Tunnel stopped.');
      const data = await tunnelService.getTunnels();
      setTunnels(data);
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to stop tunnel'));
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await tunnelService.deleteTunnel(id);
      setDeleteConfirmId(null);
      showToast('success', 'Tunnel deleted.');
      const data = await tunnelService.getTunnels();
      setTunnels(data);
    } catch (err) {
      setDeleteConfirmId(null);
      showToast('error', getErrorMessage(err, 'Failed to delete tunnel'));
    }
  };

  // ── Uptime format ──
  const formatUptime = (timestamp?: number): string => {
    if (!timestamp) return 'Offline';
    const seconds = Math.floor(Date.now() / 1000) - timestamp;
    if (seconds < 0) return 'Just started';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return hrs > 0 ? `${hrs}h ${mins}m active` : `${mins}m active`;
  };

  // ── Render ──
  return (
    <div className="space-y-6">
      {/* ── Toast Notification ── */}
      {toast && (
        <div
          className={`fixed top-20 right-4 z-[60] px-4 py-3 rounded-xl shadow-2xl border text-sm font-medium flex items-center gap-2 animate-in slide-in-from-top-2 ${toast.type === 'success'
            ? 'bg-primary-500/10 border-primary-500/20 text-primary-400'
            : 'bg-red-500/10 border-red-500/20 text-red-400'
            }`}
        >
          {toast.message}
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <HardDrive className="w-6 h-6 text-primary-500" />
            Tunnel Management Engine
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure Bridge (Iran) and Exit (Overseas) reverse tunnels with
            dynamic cryptographic obfuscation.
          </p>
        </div>
        <button
          onClick={openAddModal}
          className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-semibold rounded-xl shadow-lg shadow-primary-500/20 transition-all text-sm"
        >
          <Plus className="w-4 h-4 font-bold" />
          Add New Tunnel
        </button>
      </div>

      {/* ── Tunnels Grid ── */}
      {loading ? (
        <div className="flex justify-center py-12">
          <Activity className="w-8 h-8 animate-spin text-primary-500" />
        </div>
      ) : tunnels.length === 0 ? (
        <div className="text-center py-16 bg-[#111111]/30 border border-[#222222] rounded-2xl">
          <HardDrive className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">
            No active tunnels configured
          </h3>
          <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
            Click the button above to establish your first reverse tunnel
            between Iran and your Overseas server.
          </p>
          <button
            onClick={openAddModal}
            className="mt-6 px-4 py-2 bg-[#1a1a1a] hover:bg-slate-700 text-primary-400 font-medium rounded-xl text-sm transition-colors border border-[#222222]"
          >
            Establish First Tunnel
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tunnels.map((t) => (
            <div
              key={t.id}
              className={`bg-[#111111]/60 border rounded-2xl p-6 shadow-xl relative flex flex-col justify-between transition-all ${t.status === 'active'
                ? 'border-primary-500/30 shadow-primary-500/5'
                : 'border-[#222222]'
                }`}
            >
              {/* Card Header */}
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`w-3 h-3 rounded-full ${t.status === 'active'
                        ? 'bg-primary-500 shadow-lg shadow-primary-500/50'
                        : 'bg-slate-600'
                        }`}
                    />
                    <h3 className="font-bold text-white tracking-tight text-lg">
                      {t.name}
                    </h3>
                  </div>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${t.mode === 'iran'
                      ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                      : 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                      }`}
                  >
                    {t.mode}
                  </span>
                </div>

                {/* Info Grid */}
                <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-3.5 space-y-2 text-xs font-medium text-slate-300">
                  <div className="flex justify-between items-center py-0.5 border-b border-[#222222]/60">
                    <span className="text-slate-500">Protocol:</span>
                    <span className="uppercase text-primary-400 font-bold tracking-wide">
                      {t.protocol.replace('_', ' ')}
                    </span>
                  </div>

                  {t.mode === 'iran' ? (
                    <>
                      <div className="flex justify-between items-center py-0.5 border-b border-[#222222]/60">
                        <span className="text-slate-500">Overseas Exit:</span>
                        <span className="font-mono text-white">
                          {t.remote_ip}:{t.remote_port}
                        </span>
                      </div>
                      <div className="flex justify-between items-center py-0.5">
                        <span className="text-slate-500">Local Ports:</span>
                        <span className="font-mono text-primary-300 bg-primary-500/10 px-1.5 py-0.5 rounded border border-primary-500/20">
                          {t.local_ports}
                        </span>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="flex justify-between items-center py-0.5 border-b border-[#222222]/60">
                        <span className="text-slate-500">Listen Port:</span>
                        <span className="font-mono text-white">
                          {t.remote_port}
                        </span>
                      </div>
                      <div className="flex justify-between items-center py-0.5">
                        <span className="text-slate-500">Target Dest:</span>
                        <span className="font-mono text-primary-300 bg-primary-500/10 px-1.5 py-0.5 rounded border border-primary-500/20">
                          127.0.0.1:{t.target_port}
                        </span>
                      </div>
                    </>
                  )}

                  {t.protocol === 'kcp' && (
                    <div className="flex justify-between items-center py-0.5 border-t border-[#222222]/60 text-slate-400">
                      <span>KCP Stack Mode:</span>
                      <span className="uppercase font-semibold text-white">
                        {t.kcp_mode}
                      </span>
                    </div>
                  )}
                  {t.protocol === 'sni_spoof' && (
                    <div className="flex justify-between items-center py-0.5 border-t border-[#222222]/60 text-slate-400 truncate">
                      <span>Spoofed Host SNI:</span>
                      <span className="font-mono text-white truncate max-w-[140px]">
                        {t.spoof_sni}
                      </span>
                    </div>
                  )}
                  {t.protocol === 'ip_spoof' && (
                    <div className="flex justify-between items-center py-0.5 border-t border-[#222222]/60 text-slate-400">
                      <span>Fake Target IP:</span>
                      <span className="font-mono text-white">
                        {t.fake_ip}
                      </span>
                    </div>
                  )}
                </div>

                {/* Bandwidth */}
                <div className="mt-4 flex items-center justify-between text-xs text-slate-400 px-1">
                  <div className="flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5 text-primary-500" />
                    <span>In: {formatBytes(t.bytes_in)}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ArrowRight className="w-3.5 h-3.5 text-blue-400" />
                    <span>Out: {formatBytes(t.bytes_out)}</span>
                  </div>
                </div>
              </div>

              {/* Card Actions */}
              <div className="mt-6 pt-4 border-t border-[#222222] flex items-center justify-between gap-2">
                <div className="text-xs text-slate-500 font-mono">
                  {formatUptime(t.uptime)}
                </div>
                <div className="flex items-center gap-1.5">
                  {t.status === 'active' ? (
                    <button
                      onClick={() => handleStop(t.id)}
                      className="px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-semibold rounded-lg border border-red-500/20 flex items-center gap-1.5 text-xs transition-colors"
                    >
                      <Square className="w-3.5 h-3.5 fill-current" /> Stop
                    </button>
                  ) : (
                    <button
                      onClick={() => handleStart(t.id)}
                      className="px-3 py-1.5 bg-primary-500/10 hover:bg-primary-500/20 text-primary-400 font-semibold rounded-lg border border-primary-500/20 flex items-center gap-1.5 text-xs transition-colors"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" /> Start
                    </button>
                  )}
                  <button
                    onClick={() => openEditModal(t)}
                    className="p-1.5 bg-[#1a1a1a] hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-[#222222]"
                  >
                    <Edit className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setDeleteConfirmId(t.id)}
                    className="p-1.5 bg-[#1a1a1a] hover:bg-red-500/20 text-slate-400 hover:text-red-400 rounded-lg transition-colors border border-[#222222] hover:border-red-500/30"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Delete Confirmation Modal ── */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111111]border border-[#222222] rounded-2xl max-w-sm w-full p-6 shadow-2xl">
            <h3 className="text-lg font-bold text-white mb-2">
              Confirm Deletion
            </h3>
            <p className="text-sm text-slate-400 mb-6">
              Are you sure you want to permanently delete this tunnel? This
              action cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-2 bg-[#1a1a1a] hover:bg-slate-700 text-slate-300 font-semibold rounded-xl text-sm"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirmId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-bold rounded-xl text-sm"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add / Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm flex items-start sm:items-center justify-center p-2 sm:p-4 pt-12 sm:pt-4">
          <div className="bg-[#111111] border border-[#222222] rounded-2xl w-full max-w-xl p-4 sm:p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[#222222] pb-4 mb-4">
              <h2 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 sm:w-6 sm:h-6 text-primary-500" />
                {editingId ? 'Edit Tunnel Node' : 'Configure New Tunnel Node'}
              </h2>
              <button
                onClick={() => setModalOpen(false)}
                className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-[#1a1a1a]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {saveError && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 text-red-400 p-3 rounded-xl text-sm">
                {saveError}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <fieldset disabled={saving}>
                <div className="space-y-4">
                  {/* Name */}
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Tunnel Node Name
                    </label>
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Bridge_Tehran_to_Frankfurt"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500"
                    />
                  </div>

                  {/* Mode + Protocol */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        Server Side Role
                      </label>
                      <select
                        value={mode}
                        onChange={(e) => setMode(e.target.value as 'iran' | 'overseas')}
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-semibold"
                      >
                        <option value="iran">Iran (Bridge / Initiator)</option>
                        <option value="overseas">Overseas (Node / Listener)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        Tunnel Protocol
                      </label>
                      <select
                        value={protocol}
                        onChange={(e) => setProtocol(e.target.value as 'kcp' | 'tcp' | 'ip_spoof' | 'sni_spoof')}
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white font-bold focus:outline-none focus:border-primary-500 uppercase"
                      >
                        <option value="tcp">TCP (Raw Framed AEAD)</option>
                        <option value="kcp">KCP (Reliable UDP)</option>
                        <option value="sni_spoof">SNI Spoofing</option>
                        <option value="ip_spoof">IP Spoofing</option>
                      </select>
                    </div>
                  </div>

                  {/* Iran fields */}
                  {mode === 'iran' && (
                    <>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                            Overseas Server IP
                          </label>
                          <input
                            type="text"
                            required
                            value={remoteIp}
                            onChange={(e) => setRemoteIp(e.target.value)}
                            placeholder="1.2.3.4"
                            className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                            Overseas Listen Port
                          </label>
                          <input
                            type="number"
                            required
                            min={1}
                            max={65535}
                            value={remotePort}
                            onChange={(e) => setRemotePort(Number(e.target.value))}
                            className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                          Local Listen Port(s)
                          <span className="normal-case font-normal text-[10px] ml-2 text-slate-600">
                            Single: 80 | Multi: 80,880 | Range: 80-100
                          </span>
                        </label>
                        <input
                          type="text"
                          required
                          value={localPorts}
                          onChange={(e) => setLocalPorts(e.target.value)}
                          placeholder="80 or 80,880 or 80-100"
                          className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-primary-300 font-mono focus:outline-none focus:border-primary-500"
                        />
                      </div>
                    </>
                  )}

                  {/* Overseas fields */}
                  {mode === 'overseas' && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                          Connection Listen Port
                        </label>
                        <input
                          type="number"
                          required
                          min={1}
                          max={65535}
                          value={remotePort}
                          onChange={(e) => setRemotePort(Number(e.target.value))}
                          className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                          Target Forward Port
                        </label>
                        <input
                          type="number"
                          required
                          min={1}
                          max={65535}
                          value={targetPort}
                          onChange={(e) => setTargetPort(Number(e.target.value))}
                          placeholder="2096"
                          className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                        />
                      </div>
                    </div>
                  )}

                  {/* Encryption Key */}
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center justify-between">
                      <span>Encryption Key</span>
                      <button
                        type="button"
                        onClick={handleKeygen}
                        className="text-xs text-primary-400 hover:text-primary-300 font-bold flex items-center gap-1 underline"
                      >
                        <Key className="w-3 h-3" /> Generate
                      </button>
                    </label>
                    <input
                      type="text"
                      required
                      value={encryptionKey}
                      onChange={(e) => setEncryptionKey(e.target.value)}
                      placeholder="Click Generate or paste shared key"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3 sm:px-4 py-2 sm:py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>

                  {/* KCP Options */}
                  {protocol === 'kcp' && (
                    <div className="bg-[#0a0a0a] border border-[#222222] p-3 sm:p-4 rounded-xl space-y-2">
                      <label className="block text-xs font-semibold uppercase tracking-wider text-primary-400 flex items-center gap-1.5">
                        <HelpCircle className="w-4 h-4" /> KCP Stack Mode
                      </label>
                      <select
                        value={kcpMode}
                        onChange={(e) => setKcpMode(e.target.value as 'normal' | 'fast' | 'fast2' | 'fast3')}
                        className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white focus:outline-none"
                      >
                        <option value="normal">Normal - Bandwidth Optimized</option>
                        <option value="fast">Fast - Quick Recovery</option>
                        <option value="fast2">Fast2 - Low Latency + Recovery</option>
                        <option value="fast3">Fast3 - Extreme Low Latency</option>
                      </select>
                    </div>
                  )}

                  {/* SNI Options */}
                  {protocol === 'sni_spoof' && (
                    <div className="bg-[#0a0a0a] border border-[#222222] p-3 sm:p-4 rounded-xl space-y-2">
                      <label className="block text-xs font-semibold uppercase tracking-wider text-primary-400 flex items-center gap-1.5">
                        <HelpCircle className="w-4 h-4" /> Spoofed SNI Domain
                      </label>
                      <input
                        type="text"
                        required
                        value={spoofSni}
                        onChange={(e) => setSpoofSni(e.target.value)}
                        placeholder="www.aparat.com"
                        className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                      />
                      <p className="text-[11px] text-slate-500">
                        Domain used in TLS ClientHello SNI to bypass DPI filters.
                      </p>
                    </div>
                  )}

                  {/* IP Spoof Options */}
                  {protocol === 'ip_spoof' && (
                    <div className="bg-[#0a0a0a] border border-[#222222] p-3 sm:p-4 rounded-xl space-y-2">
                      <label className="block text-xs font-semibold uppercase tracking-wider text-primary-400 flex items-center gap-1.5">
                        <HelpCircle className="w-4 h-4" /> Fake Source IP
                      </label>
                      <input
                        type="text"
                        required
                        value={fakeIp}
                        onChange={(e) => setFakeIp(e.target.value)}
                        placeholder="185.10.20.30"
                        className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                      />
                      <p className="text-[11px] text-slate-500">
                        Spoofed source IP for encapsulated packet headers.
                      </p>
                    </div>
                  )}
                </div>
              </fieldset>

              {/* Actions */}
              <div className="pt-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-end gap-2 sm:gap-3 border-t border-[#222222]">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2.5 bg-[#1a1a1a] hover:bg-[#222222] text-slate-300 font-semibold rounded-xl text-sm transition-colors order-2 sm:order-1"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-6 py-2.5 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-bold rounded-xl shadow-lg shadow-primary-500/20 transition-all text-sm disabled:opacity-50 flex items-center justify-center gap-2 order-1 sm:order-2"
                >
                  {saving && <Activity className="w-4 h-4 animate-spin" />}
                  Save Tunnel Configuration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};