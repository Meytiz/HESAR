import React, { useState } from 'react';
import {
  Radio,
  Send,
  RefreshCw,
  CheckCircle2,
  ShieldAlert,
  Globe,
  Layers,
  Zap,
  HelpCircle,
} from 'lucide-react';
import { toolService } from '../services/api';
import { TestResult } from '../types';

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

// ✅ IP validation
const isValidIP = (ip: string): boolean => {
  if (!ip) return false;
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return !isNaN(n) && n >= 0 && n <= 255 && p === String(n);
  });
};

type ProbeTab = 'tcp' | 'tls' | 'quic';

export const Tester: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ProbeTab>('quic');

  const [targetIp, setTargetIp] = useState('');
  const [port, setPort] = useState(443);
  const [serverName, setServerName] = useState('');
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const switchTab = (tab: ProbeTab) => {
    setActiveTab(tab);
    setResult(null);
    setFormError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setResult(null);

    if (!isValidIP(targetIp)) {
      setFormError('Please enter a valid IPv4 address.');
      return;
    }
    if (port < 1 || port > 65535) {
      setFormError('Port must be between 1 and 65535.');
      return;
    }
    if (activeTab === 'tls' && !serverName.trim()) {
      setFormError('Server name (SNI) is required for the TLS probe.');
      return;
    }

    setTesting(true);
    try {
      let res: TestResult;
      if (activeTab === 'tcp') {
        res = await toolService.testTCP(targetIp, port);
      } else if (activeTab === 'tls') {
        res = await toolService.testTLS(targetIp, port, serverName.trim());
      } else {
        res = await toolService.testQUIC(targetIp, port);
      }
      setResult(res);
    } catch (err) {
      setResult({
        success: false,
        latency_ms: 0,
        details: getErrorMessage(err, 'Probe request failed.'),
      });
    } finally {
      setTesting(false);
    }
  };

  const tabDescriptions: Record<ProbeTab, string> = {
    quic: 'Attempts a genuine QUIC handshake (UDP). Success means the path is open for QUIC/HTTP-3 — the primary vNext transport.',
    tls: 'Performs a real TLS handshake over TCP and reports the negotiated version. TLS 1.3 endpoints are required by the HESAR fallback transport.',
    tcp: 'A plain TCP three-way handshake. Connectivity only — no protocol is verified.',
  };

  return (
    <div className="p-4 sm:p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-primary-500/10 border border-primary-500/30 flex items-center justify-center">
          <Radio className="w-5 h-5 text-primary-400" />
        </div>
        <div>
          <h1 className="text-xl font-black text-white">Protocol Tester</h1>
          <p className="text-xs text-slate-500">
            Real protocol probes for the vNext transports. The legacy SNI/IP
            spoof "diagnostics" (which reported false positives) were removed.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="grid grid-cols-3 gap-2">
        <button
          type="button"
          onClick={() => switchTab('quic')}
          className={`flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl border text-xs font-bold uppercase tracking-wider transition-colors ${
            activeTab === 'quic'
              ? 'bg-primary-500/15 border-primary-500/50 text-primary-300'
              : 'bg-[#0a0a0a] border-[#222222] text-slate-400 hover:border-[#333333]'
          }`}
        >
          <Zap className="w-4 h-4" /> QUIC / UDP
        </button>
        <button
          type="button"
          onClick={() => switchTab('tls')}
          className={`flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl border text-xs font-bold uppercase tracking-wider transition-colors ${
            activeTab === 'tls'
              ? 'bg-primary-500/15 border-primary-500/50 text-primary-300'
              : 'bg-[#0a0a0a] border-[#222222] text-slate-400 hover:border-[#333333]'
          }`}
        >
          <Layers className="w-4 h-4" /> TLS 1.3
        </button>
        <button
          type="button"
          onClick={() => switchTab('tcp')}
          className={`flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl border text-xs font-bold uppercase tracking-wider transition-colors ${
            activeTab === 'tcp'
              ? 'bg-primary-500/15 border-primary-500/50 text-primary-300'
              : 'bg-[#0a0a0a] border-[#222222] text-slate-400 hover:border-[#333333]'
          }`}
        >
          <Globe className="w-4 h-4" /> TCP
        </button>
      </div>

      <div className="bg-[#0d0d0d] border border-[#222222] rounded-2xl p-4 sm:p-6">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
          <HelpCircle className="w-4 h-4 text-primary-400" />
          What this probe does
        </div>
        <p className="text-[12px] text-slate-500 leading-relaxed mb-5">
          {tabDescriptions[activeTab]}
        </p>

        {formError && (
          <div className="mb-4 flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            {formError}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <fieldset disabled={testing} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Target IPv4
                </label>
                <input
                  type="text"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="203.0.113.10"
                  className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Port
                </label>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={port}
                  onChange={(e) => setPort(Number(e.target.value))}
                  className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                />
              </div>
            </div>

            {activeTab === 'tls' && (
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Server Name (SNI)
                </label>
                <input
                  type="text"
                  value={serverName}
                  onChange={(e) => setServerName(e.target.value)}
                  placeholder="node.example.com"
                  className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={testing}
              className="w-full flex items-center justify-center gap-2 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 text-black font-black rounded-xl px-4 py-3 text-sm uppercase tracking-wider transition-colors"
            >
              {testing ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              {testing ? 'Probing…' : `Launch ${activeTab.toUpperCase()} Probe`}
            </button>
          </fieldset>
        </form>

        <div className="mt-4 text-[11px] text-slate-600 leading-relaxed">
          Note: private, loopback and link-local targets (including the cloud
          metadata IP) are rejected server-side by the SSRF guard.
        </div>
      </div>

      {/* Result */}
      {testing && (
        <div className="flex items-center justify-center gap-2 text-slate-500 text-sm py-6">
          <RefreshCw className="w-4 h-4 animate-spin" /> Running probe…
        </div>
      )}
      {!testing && result && (
        <div
          className={`rounded-2xl border p-4 sm:p-5 ${
            result.success
              ? 'bg-emerald-500/5 border-emerald-500/30'
              : 'bg-red-500/5 border-red-500/30'
          }`}
        >
          <div className="flex items-start gap-3">
            {result.success ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            )}
            <div className="min-w-0">
              <div className="text-sm font-bold text-white mb-1">
                {result.success ? 'Probe succeeded' : 'Probe failed'}
                <span className="ml-2 text-xs font-mono text-slate-500">
                  {result.latency_ms} ms
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed break-words">
                {result.details}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Tester;
