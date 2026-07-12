import React, { useState } from 'react';
import {
  Radio,
  Send,
  RefreshCw,
  CheckCircle2,
  ShieldAlert,
  Globe,
  Layers,
  ArrowRight,
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

export const Tester: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'sni' | 'ip'>('sni');

  // SNI Form
  const [sniTargetIp, setSniTargetIp] = useState('');
  const [sniPort, setSniPort] = useState(443);
  const [sniDomain, setSniDomain] = useState('www.aparat.com');
  const [sniTesting, setSniTesting] = useState(false);
  const [sniResult, setSniResult] = useState<TestResult | null>(null);
  const [sniError, setSniError] = useState<string | null>(null);

  // IP Spoof Form
  const [ipTargetIp, setIpTargetIp] = useState('');
  const [ipPort, setIpPort] = useState(8443);
  const [fakeIp, setFakeIp] = useState('185.10.20.30');
  const [ipTesting, setIpTesting] = useState(false);
  const [ipResult, setIpResult] = useState<TestResult | null>(null);
  const [ipError, setIpError] = useState<string | null>(null);

  const handleTestSNI = async (e: React.FormEvent) => {
    e.preventDefault();
    setSniError(null);

    // ✅ Client-side validation
    if (!isValidIP(sniTargetIp)) {
      setSniError('Please enter a valid IPv4 address.');
      return;
    }
    if (sniPort < 1 || sniPort > 65535) {
      setSniError('Port must be between 1 and 65535.');
      return;
    }
    if (!sniDomain.trim()) {
      setSniError('SNI domain is required.');
      return;
    }

    setSniTesting(true);
    setSniResult(null);
    try {
      const res = await toolService.testSNI(sniTargetIp, sniPort, sniDomain);
      setSniResult(res);
    } catch (err) {
      setSniResult({
        success: false,
        latency_ms: 0,
        details: getErrorMessage(err, 'SNI Diagnostic probe failed.'),
      });
    } finally {
      setSniTesting(false);
    }
  };

  const handleTestIP = async (e: React.FormEvent) => {
    e.preventDefault();
    setIpError(null);

    // ✅ Client-side validation
    if (!isValidIP(ipTargetIp)) {
      setIpError('Please enter a valid IPv4 address.');
      return;
    }
    if (ipPort < 1 || ipPort > 65535) {
      setIpError('Port must be between 1 and 65535.');
      return;
    }
    if (!isValidIP(fakeIp)) {
      setIpError('Please enter a valid Fake IP address.');
      return;
    }

    setIpTesting(true);
    setIpResult(null);
    try {
      const res = await toolService.testIP(ipTargetIp, ipPort, fakeIp);
      setIpResult(res);
    } catch (err) {
      setIpResult({
        success: false,
        latency_ms: 0,
        details: getErrorMessage(err, 'IP Spoof Diagnostic probe failed.'),
      });
    } finally {
      setIpTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Radio className="w-6 h-6 text-primary-500" />
            Live Deep Packet Inspection Diagnostic Bench
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Test real-world penetration and DPI bypass behavior for TLS
            ClientHello SNI masking and custom IP encapsulation.
          </p>
        </div>

        <div className="flex bg-[#0a0a0a] p-1.5 border border-[#222222] rounded-xl space-x-1">
          <button
            onClick={() => {
              setActiveTab('sni');
              setSniResult(null);
              setSniError(null);
            }}
            className={`px-4 py-2 rounded-lg font-bold text-xs flex items-center gap-2 transition-all ${
              activeTab === 'sni'
                ? 'bg-primary-500 text-slate-950 shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Globe className="w-4 h-4" /> SNI Spoofing Test
          </button>
          <button
            onClick={() => {
              setActiveTab('ip');
              setIpResult(null);
              setIpError(null);
            }}
            className={`px-4 py-2 rounded-lg font-bold text-xs flex items-center gap-2 transition-all ${
              activeTab === 'ip'
                ? 'bg-primary-500 text-slate-950 shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Layers className="w-4 h-4" /> IP Spoofing Test
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── Left: Form ── */}
        {activeTab === 'sni' ? (
          <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
            <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-primary-400" />
              Configure TLS ClientHello SNI Diagnostic Probe
            </h2>

            {sniError && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 text-red-400 p-3 rounded-xl text-sm">
                {sniError}
              </div>
            )}

            <form onSubmit={handleTestSNI} className="space-y-4">
              <fieldset disabled={sniTesting}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Target Destination Host IP
                    </label>
                    <input
                      type="text"
                      required
                      value={sniTargetIp}
                      onChange={(e) => setSniTargetIp(e.target.value)}
                      placeholder="e.g. 1.2.3.4"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Target Destination HTTPS Port
                    </label>
                    <input
                      type="number"
                      required
                      min={1}
                      max={65535}
                      value={sniPort}
                      onChange={(e) => setSniPort(Number(e.target.value))}
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Spoofed Domain SNI to Insert
                    </label>
                    <input
                      type="text"
                      required
                      value={sniDomain}
                      onChange={(e) => setSniDomain(e.target.value)}
                      placeholder="www.aparat.com"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-primary-300 focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>
                </div>
              </fieldset>
              <div className="pt-2">
                <button
                  type="submit"
                  disabled={sniTesting}
                  className="w-full py-3 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-bold rounded-xl shadow-lg shadow-primary-500/20 transition-all text-sm flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {sniTesting ? (
                    <RefreshCw className="w-5 h-5 animate-spin" />
                  ) : (
                    <Send className="w-5 h-5" />
                  )}
                  {sniTesting
                    ? 'Executing Handshake Penetration...'
                    : 'Launch Live SNI Penetration Probe'}
                </button>
              </div>
            </form>

            <div className="mt-6 border-t border-[#222222] pt-4 flex items-start gap-2.5 text-xs text-slate-500">
              <HelpCircle className="w-4 h-4 text-primary-500 flex-shrink-0 mt-0.5" />
              <p>
                Injects a customized ClientHello packet. Middleboxes inspect the
                allowed SNI hostname and open the TCP state table, passing
                subsequent DPI inspection.
              </p>
            </div>
          </div>
        ) : (
          <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
            <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <Layers className="w-5 h-5 text-primary-400" />
              Configure Raw Encapsulated IP Diagnostic Probe
            </h2>

            {ipError && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 text-red-400 p-3 rounded-xl text-sm">
                {ipError}
              </div>
            )}

            <form onSubmit={handleTestIP} className="space-y-4">
              <fieldset disabled={ipTesting}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Target Destination Server IP
                    </label>
                    <input
                      type="text"
                      required
                      value={ipTargetIp}
                      onChange={(e) => setIpTargetIp(e.target.value)}
                      placeholder="e.g. 1.2.3.4"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Target Destination Listener Port
                    </label>
                    <input
                      type="number"
                      required
                      min={1}
                      max={65535}
                      value={ipPort}
                      onChange={(e) => setIpPort(Number(e.target.value))}
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Fake Encapsulation IP Header to Spoof
                    </label>
                    <input
                      type="text"
                      required
                      value={fakeIp}
                      onChange={(e) => setFakeIp(e.target.value)}
                      placeholder="185.10.20.30"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-4 py-2.5 text-sm text-primary-300 focus:outline-none focus:border-primary-500 font-mono"
                    />
                  </div>
                </div>
              </fieldset>
              <div className="pt-2">
                <button
                  type="submit"
                  disabled={ipTesting}
                  className="w-full py-3 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-bold rounded-xl shadow-lg shadow-primary-500/20 transition-all text-sm flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {ipTesting ? (
                    <RefreshCw className="w-5 h-5 animate-spin" />
                  ) : (
                    <Send className="w-5 h-5" />
                  )}
                  {ipTesting
                    ? 'Transmitting Outer Payload...'
                    : 'Transmit Encapsulated IP Probe'}
                </button>
              </div>
            </form>

            <div className="mt-6 border-t border-[#222222] pt-4 flex items-start gap-2.5 text-xs text-slate-500">
              <HelpCircle className="w-4 h-4 text-primary-500 flex-shrink-0 mt-0.5" />
              <p>
                Packages raw TCP/UDP stream inside an obfuscated Fake IP
                envelope. Masks underlying traffic signatures from
                destination-aware firewalls.
              </p>
            </div>
          </div>
        )}

        {/* ── Right: Results ── */}
        <div className="bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-bold text-white mb-6 border-b border-[#222222] pb-3 flex items-center gap-2">
              <Radio className="w-5 h-5 text-primary-500" />
              Probe Execution Diagnostic Feedback
            </h2>

            {(activeTab === 'sni' ? sniTesting : ipTesting) ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <RefreshCw className="w-12 h-12 animate-spin text-primary-500 mb-4" />
                <h3 className="font-bold text-white text-base">
                  Transmitting Deep Packets...
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  Awaiting real-time firewall ACK / Drop behavior analysis
                </p>
              </div>
            ) : (activeTab === 'sni' ? sniResult : ipResult) ? (
              (() => {
                const res = (activeTab === 'sni'
                  ? sniResult
                  : ipResult)!;
                return (
                  <div className="space-y-6">
                    {/* Status */}
                    <div
                      className={`p-5 rounded-2xl border flex items-center gap-4 ${
                        res.success
                          ? 'bg-primary-500/10 border-primary-500/30 text-primary-400'
                          : 'bg-red-500/10 border-red-500/30 text-red-400'
                      }`}
                    >
                      {res.success ? (
                        <CheckCircle2 className="w-10 h-10 text-primary-500 flex-shrink-0" />
                      ) : (
                        <ShieldAlert className="w-10 h-10 text-red-500 flex-shrink-0" />
                      )}
                      <div>
                        <div className="font-extrabold text-lg text-white">
                          {res.success
                            ? 'DPI FILTER BYPASS SUCCESSFUL!'
                            : 'PENETRATION PROBE BLOCKED'}
                        </div>
                        <div className="text-xs mt-0.5 opacity-90 font-medium">
                          {res.success
                            ? 'The GFW / DPI firewall allowed the connection state across without dropping packets.'
                            : 'Connection reset or blocked by active DPI matching middleware.'}
                        </div>
                      </div>
                    </div>

                    {/* Latency */}
                    {res.success && (
                      <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-4 flex items-center justify-between">
                        <span className="text-xs text-slate-400 uppercase font-semibold">
                          Handshake RTT Latency
                        </span>
                        <span className="text-xl font-bold text-primary-400 font-mono">
                          {res.latency_ms} ms
                        </span>
                      </div>
                    )}

                    {/* Details */}
                    <div>
                      <span className="text-xs text-slate-500 uppercase font-bold tracking-wider">
                        Raw Server Transmission Feedback
                      </span>
                      <div className="mt-2 bg-[#0a0a0a] border border-[#222222] rounded-xl p-4 font-['JetBrains_Mono'] text-xs text-slate-300 leading-relaxed overflow-x-auto">
                        <div className="flex items-center gap-2 text-primary-500 font-bold mb-1">
                          <ArrowRight className="w-3.5 h-3.5" /> Output Event
                          Details:
                        </div>
                        {res.details}
                      </div>
                    </div>
                  </div>
                );
              })()
            ) : (
              <div className="flex flex-col items-center justify-center py-20 text-center bg-[#111111]/30 border border-[#222222] rounded-2xl">
                <Radio className="w-12 h-12 text-slate-700 mb-3" />
                <div className="text-sm font-semibold text-slate-400">
                  Ready to execute probe
                </div>
                <div className="text-xs text-slate-600 mt-1 max-w-xs">
                  Fill in your target parameters on the left and initiate the
                  test to receive live diagnostic metrics.
                </div>
              </div>
            )}
          </div>

          <div className="mt-8 text-center text-xs text-slate-600">
            Powered by independent asynchronous protocol testers modeled after
            cutting-edge DPI research.
          </div>
        </div>
      </div>
    </div>
  );
};