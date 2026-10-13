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
  Copy,
  Upload,
  Sparkles,
  Server,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { networkService, toolService, tunnelService } from '../services/api';
import {
  NetworkProfile,
  NetworkRuntimeItem,
  TunnelCarrier,
  TunnelConfig,
  TunnelProtocol,
} from '../types';

const DEFAULT_PROFILES: NetworkProfile[] = [
  {
    name: 'balanced',
    label: 'Balanced (Auto QUIC/WSS)',
    summary: 'Uses QUIC first and falls back to TLS/WebSocket when UDP is degraded.',
    recommended_protocol: 'auto',
    carrier: 'direct',
  },
  {
    name: 'tcp-only',
    label: 'TCP / CDN Compatible (WSS)',
    summary: 'Uses TLS 1.3 + WebSocket over TCP for UDP-blocked paths.',
    recommended_protocol: 'wss',
    carrier: 'direct',
  },
  {
    name: 'tls-fragment',
    label: 'Fragmented TLS Handshake (WSS)',
    summary: 'Splits initial TLS records across smaller TCP writes before WebSocket upgrade.',
    recommended_protocol: 'wss',
    carrier: 'direct',
  },
  {
    name: 'shaped-wss',
    label: 'Shaped WSS (Padded Frames)',
    summary: 'Pads inner tunnel chunks before sending binary WebSocket frames over TLS.',
    recommended_protocol: 'wss-shaped',
    carrier: 'direct',
  },
  {
    name: 'udp-lossy',
    label: 'Lossy UDP / High RTT (QUIC)',
    summary: 'Uses QUIC with conservative MTU discovery settings for unstable paths.',
    recommended_protocol: 'quic',
    carrier: 'direct',
  },
  {
    name: 'raw-packet',
    label: 'Raw Packet Bypass (Managed Paqet)',
    summary: 'Manages a local Paqet KCP raw-packet link via the HESAR network agent.',
    recommended_protocol: 'quic',
    carrier: 'paqet',
  },
  {
    name: 'xray',
    label: 'XHTTP + REALITY (Managed Xray)',
    summary: 'Manages a local Xray-core XHTTP/REALITY link via the HESAR network agent.',
    recommended_protocol: 'tcp',
    carrier: 'xray',
  },
  {
    name: 'hysteria',
    label: 'UDP Obfuscated (Managed Hysteria 2)',
    summary: 'Manages a local Hysteria 2 QUIC/Salamander link via the HESAR network agent.',
    recommended_protocol: 'tcp',
    carrier: 'hysteria',
  },
  {
    name: 'l3-gre',
    label: 'Layer-3 GRE + HESAR',
    summary: 'Manages a point-to-point GRE interface via the HESAR network agent.',
    recommended_protocol: 'quic',
    carrier: 'gre',
  },
  {
    name: 'l3-ipip',
    label: 'Layer-3 IPIP + HESAR',
    summary: 'Manages a point-to-point IPIP interface via the HESAR network agent.',
    recommended_protocol: 'quic',
    carrier: 'ipip',
  },
];

const getErrorMessage = (err: unknown, fallback: string): string => {
  if (err && typeof err === 'object' && 'response' in err) {
    const axiosErr = err as { response?: { data?: unknown } };
    const data = axiosErr.response?.data;
    if (typeof data === 'string' && data.trim()) return data.trim();
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
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const copyTextWithFallback = async (text: string): Promise<boolean> => {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall back to execCommand below
    }
  }
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const copied = document.execCommand('copy');
    document.body.removeChild(textarea);
    return copied;
  } catch {
    return false;
  }
};

export const Tunnels: React.FC = () => {
  const [tunnels, setTunnels] = useState<TunnelConfig[]>([]);
  const [profiles, setProfiles] = useState<NetworkProfile[]>(DEFAULT_PROFILES);
  const [agentAvailable, setAgentAvailable] = useState<boolean | null>(null);
  const [agentMessage, setAgentMessage] = useState<string>('');
  const [runtimes, setRuntimes] = useState<Record<string, NetworkRuntimeItem>>({});
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Peer export / import modals
  const [peerExportJson, setPeerExportJson] = useState<string | null>(null);
  const [peerExportNotice, setPeerExportNotice] = useState<string>('');
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importJsonText, setImportJsonText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);

  // Form State
  const [name, setName] = useState('');
  const [mode, setMode] = useState<'iran' | 'overseas'>('overseas');
  const [networkProfile, setNetworkProfile] = useState<string>('balanced');
  const [protocol, setProtocol] = useState<TunnelProtocol>('auto');
  const [carrier, setCarrier] = useState<TunnelCarrier>('direct');
  const [legacyProtocol, setLegacyProtocol] = useState<string | null>(null);

  const [localPorts, setLocalPorts] = useState('18080');
  const [remoteIp, setRemoteIp] = useState('');
  const [remotePort, setRemotePort] = useState(18081);
  const [targetHost, setTargetHost] = useState('127.0.0.1');
  const [targetPort, setTargetPort] = useState(8080);
  const [encryptionKey, setEncryptionKey] = useState('');

  // Managed carrier & WAN fields
  const [carrierPeerIp, setCarrierPeerIp] = useState('');
  const [carrierLocalIp, setCarrierLocalIp] = useState('');
  const [carrierLocalInner, setCarrierLocalInner] = useState('10.77.0.2');
  const [carrierRemoteInner, setCarrierRemoteInner] = useState('10.77.0.1');
  const [carrierMtu, setCarrierMtu] = useState(1280);
  const [carrierPort, setCarrierPort] = useState(19999);
  const [carrierAuth, setCarrierAuth] = useState('');
  const [carrierObfs, setCarrierObfs] = useState('');

  // REALITY fields
  const [realityTarget, setRealityTarget] = useState('');
  const [realityPrivateKey, setRealityPrivateKey] = useState('');
  const [realityPublicKey, setRealityPublicKey] = useState('');
  const [realityShortId, setRealityShortId] = useState('');

  // TLS & WSS fields
  const [serverName, setServerName] = useState('hesar.internal');
  const [wsPath, setWsPath] = useState('/ws');
  const [tlsFragmentSize, setTlsFragmentSize] = useState(0);
  const [tlsFragmentDelayMs, setTlsFragmentDelayMs] = useState(0);
  const [tlsCertPem, setTlsCertPem] = useState('');
  const [tlsKeyPem, setTlsKeyPem] = useState('');
  const [tlsCaPem, setTlsCaPem] = useState('');
  const [tlsCertFile, setTlsCertFile] = useState('');
  const [tlsKeyFile, setTlsKeyFile] = useState('');
  const [tlsCaFile, setTlsCaFile] = useState('');

  // Protocol & Advanced options
  const [kcpMode, setKcpMode] = useState<'normal' | 'fast' | 'fast2' | 'fast3'>('fast3');
  const [quicDisablePmtu, setQuicDisablePmtu] = useState(false);
  const [listenAddress, setListenAddress] = useState('');
  const [underlayInterface, setUnderlayInterface] = useState('');
  const [proxyUrl, setProxyUrl] = useState('');
  const [dialTimeoutSeconds, setDialTimeoutSeconds] = useState(10);
  const [idleTimeoutSeconds, setIdleTimeoutSeconds] = useState(60);
  const [fallbackCooldownSeconds, setFallbackCooldownSeconds] = useState(60);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [saving, setSaving] = useState(false);
  const [generatingCreds, setGeneratingCreds] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

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

  const fetchAll = useCallback(async () => {
    try {
      const [tunnelList, runtimeStatus] = await Promise.all([
        tunnelService.getTunnels(),
        networkService.getRuntime().catch(() => null),
      ]);
      setTunnels(tunnelList);
      if (runtimeStatus) {
        const isAvail = runtimeStatus.available !== false && runtimeStatus.ok !== false;
        setAgentAvailable(isAvail);
        setAgentMessage(runtimeStatus.message || '');
        const map: Record<string, NetworkRuntimeItem> = {};
        for (const item of runtimeStatus.runtimes || []) {
          map[item.id] = item;
        }
        setRuntimes(map);
      }
    } catch (err) {
      console.error('Failed to fetch tunnels:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    networkService
      .getProfiles()
      .then((list) => {
        if (mounted && Array.isArray(list) && list.length > 0) {
          setProfiles(list);
        }
      })
      .catch(() => {
        // Keep built-in default profiles
      });

    void fetchAll();
    const interval = setInterval(() => {
      if (mounted) void fetchAll();
    }, 3000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [fetchAll]);

  const applyProfilePreset = (
    profileName: string,
    targetMode: 'iran' | 'overseas' = mode
  ) => {
    setNetworkProfile(profileName);
    switch (profileName) {
      case 'balanced':
        setCarrier('direct');
        setProtocol('auto');
        setQuicDisablePmtu(false);
        break;
      case 'tcp-only':
        setCarrier('direct');
        setProtocol('wss');
        setTlsFragmentSize(0);
        setTlsFragmentDelayMs(0);
        break;
      case 'tls-fragment':
        setCarrier('direct');
        setProtocol('wss');
        setTlsFragmentSize(24);
        setTlsFragmentDelayMs(8);
        break;
      case 'shaped-wss':
        setCarrier('direct');
        setProtocol('wss-shaped');
        break;
      case 'udp-lossy':
        setCarrier('direct');
        setProtocol('quic');
        setQuicDisablePmtu(true);
        break;
      case 'raw-packet':
        setCarrier('paqet');
        setProtocol('quic');
        if (!carrierPort || carrierPort === 443) setCarrierPort(19999);
        break;
      case 'xray':
        setCarrier('xray');
        setProtocol('tcp');
        setCarrierPort(443);
        if (!serverName || serverName === 'hesar.internal') {
          setServerName('www.microsoft.com');
        }
        break;
      case 'hysteria':
        setCarrier('hysteria');
        setProtocol('tcp');
        if (!carrierPort || carrierPort < 1024) setCarrierPort(19443);
        break;
      case 'l3-gre':
        setCarrier('gre');
        setProtocol('quic');
        setCarrierMtu(1280);
        setCarrierLocalInner(targetMode === 'iran' ? '10.77.0.1' : '10.77.0.2');
        setCarrierRemoteInner(targetMode === 'iran' ? '10.77.0.2' : '10.77.0.1');
        break;
      case 'l3-ipip':
        setCarrier('ipip');
        setProtocol('quic');
        setCarrierMtu(1280);
        setCarrierLocalInner(targetMode === 'iran' ? '10.77.0.1' : '10.77.0.2');
        setCarrierRemoteInner(targetMode === 'iran' ? '10.77.0.2' : '10.77.0.1');
        break;
      default:
        break;
    }
  };

  const handleModeChange = (nextMode: 'iran' | 'overseas') => {
    setMode(nextMode);
    if (carrier === 'gre' || carrier === 'ipip') {
      if (
        (carrierLocalInner === '10.77.0.1' && carrierRemoteInner === '10.77.0.2') ||
        (carrierLocalInner === '10.77.0.2' && carrierRemoteInner === '10.77.0.1')
      ) {
        setCarrierLocalInner(nextMode === 'iran' ? '10.77.0.1' : '10.77.0.2');
        setCarrierRemoteInner(nextMode === 'iran' ? '10.77.0.2' : '10.77.0.1');
      }
    }
  };

  const populateFormFromTunnel = (t: Partial<TunnelConfig>, isEdit: boolean) => {
    setEditingId(isEdit && t.id ? t.id : null);
    setName(t.name || '');
    const tMode = t.mode === 'overseas' ? 'overseas' : 'iran';
    setMode(tMode);
    setNetworkProfile(t.network_profile || 'custom');

    const rawProto = String(t.protocol || 'quic');
    if (rawProto === 'sni_spoof' || rawProto === 'ip_spoof' || rawProto === 'tls') {
      setLegacyProtocol(rawProto);
      setProtocol('quic');
    } else {
      setLegacyProtocol(null);
      setProtocol((t.protocol as TunnelProtocol) || 'quic');
    }

    setCarrier((t.carrier as TunnelCarrier) || 'direct');
    setLocalPorts(t.local_ports || '18080');
    setRemoteIp(t.remote_ip || '');
    setRemotePort(t.remote_port || 18081);
    setTargetHost(t.target_host || '127.0.0.1');
    setTargetPort(t.target_port || 8080);
    setEncryptionKey(t.encryption_key || '');

    setCarrierPeerIp(t.carrier_peer_ip || (tMode === 'iran' ? t.remote_ip || '' : ''));
    setCarrierLocalIp(t.carrier_local_ip || '');
    setCarrierLocalInner(
      t.carrier_local_inner || (tMode === 'iran' ? '10.77.0.1' : '10.77.0.2')
    );
    setCarrierRemoteInner(
      t.carrier_remote_inner || (tMode === 'iran' ? '10.77.0.2' : '10.77.0.1')
    );
    setCarrierMtu(t.carrier_mtu || 1280);
    setCarrierPort(t.carrier_port || 19999);
    setCarrierAuth(t.carrier_auth || '');
    setCarrierObfs(t.carrier_obfs || '');

    setRealityTarget(t.reality_target || '');
    setRealityPrivateKey(t.reality_private_key || '');
    setRealityPublicKey(t.reality_public_key || '');
    setRealityShortId(t.reality_short_id || '');

    setServerName(t.server_name || 'hesar.internal');
    setWsPath(t.ws_path || '/ws');
    setTlsFragmentSize(t.tls_fragment_size || 0);
    setTlsFragmentDelayMs(t.tls_fragment_delay_ms || 0);
    setTlsCertPem(t.tls_cert_pem || '');
    setTlsKeyPem(t.tls_key_pem || '');
    setTlsCaPem(t.tls_ca_pem || '');
    setTlsCertFile(t.tls_cert_file || '');
    setTlsKeyFile(t.tls_key_file || '');
    setTlsCaFile(t.tls_ca_file || '');

    setKcpMode(t.kcp_mode || 'fast3');
    setQuicDisablePmtu(Boolean(t.quic_disable_pmtu));
    setListenAddress(t.listen_address || '');
    setUnderlayInterface(t.underlay_interface || '');
    setProxyUrl(t.proxy_url || '');
    setDialTimeoutSeconds(t.dial_timeout_seconds || 10);
    setIdleTimeoutSeconds(t.idle_timeout_seconds || 60);
    setFallbackCooldownSeconds(t.fallback_cooldown_seconds || 60);
    setShowAdvanced(
      Boolean(
        t.listen_address ||
          t.underlay_interface ||
          t.proxy_url ||
          t.tls_cert_file ||
          t.tls_key_file ||
          t.tls_ca_file
      )
    );
    setSaveError(null);
  };

  const openAddModal = () => {
    populateFormFromTunnel(
      {
        mode: 'overseas',
        network_profile: 'balanced',
        protocol: 'auto',
        carrier: 'direct',
        local_ports: '18080',
        remote_port: 18081,
        target_host: '127.0.0.1',
        target_port: 8080,
        server_name: 'hesar.internal',
        ws_path: '/ws',
      },
      false
    );
    setModalOpen(true);
  };

  const openEditModal = (t: TunnelConfig) => {
    populateFormFromTunnel(t, true);
    setModalOpen(true);
  };

  const handleKeygen = async () => {
    try {
      const keys = await toolService.keygen();
      setEncryptionKey(keys.encryption_key);
    } catch {
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      setEncryptionKey(
        Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
      );
    }
  };

  const handleGenerateTransportCredentials = async () => {
    setGeneratingCreds(true);
    setSaveError(null);
    try {
      const creds = await networkService.generateKeys(
        serverName.trim() || 'hesar.internal'
      );
      setCarrierAuth(creds.carrier_auth);
      setCarrierObfs(creds.carrier_obfs);
      setRealityPrivateKey(creds.reality_private_key);
      setRealityPublicKey(creds.reality_public_key);
      setRealityShortId(creds.reality_short_id);
      setTlsCertPem(creds.tls_cert_pem);
      setTlsKeyPem(creds.tls_key_pem);
      if (mode === 'iran') {
        setTlsCaPem(creds.tls_cert_pem);
      }
      setServerName(creds.server_name);
      if (!encryptionKey) {
        await handleKeygen();
      }
      showToast('success', 'Generated transport credentials and TLS/REALITY keys.');
    } catch (err) {
      setSaveError(getErrorMessage(err, 'Failed to generate transport credentials'));
    } finally {
      setGeneratingCreds(false);
    }
  };

  const handleCopyPeerSetup = async (t: TunnelConfig) => {
    try {
      const res = await networkService.exportPeerConfig(t.id);
      const serialized = JSON.stringify(res, null, 2);
      const copied = await copyTextWithFallback(serialized);
      setPeerExportJson(serialized);
      setPeerExportNotice(
        res.notice ||
          'Import this JSON on your Iran panel via "Import peer setup → Apply peer setup".'
      );
      if (copied) {
        showToast('success', 'Peer setup copied to clipboard.');
      }
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to export peer setup'));
    }
  };

  const handleApplyPeerSetup = (e: React.FormEvent) => {
    e.preventDefault();
    setImportError(null);
    try {
      const parsed = JSON.parse(importJsonText.trim()) as Record<string, unknown>;
      const tunnelObj = (
        parsed && typeof parsed.tunnel === 'object' && parsed.tunnel !== null
          ? parsed.tunnel
          : parsed
      ) as Partial<TunnelConfig>;
      if (!tunnelObj.protocol || !tunnelObj.encryption_key) {
        setImportError(
          'Invalid peer setup JSON: missing protocol or encryption_key.'
        );
        return;
      }
      setImportModalOpen(false);
      setImportJsonText('');
      populateFormFromTunnel({ ...tunnelObj, id: undefined }, false);
      setModalOpen(true);
      showToast(
        'success',
        'Peer setup loaded into the form. Review Local Listen Port(s) and click Save.'
      );
    } catch {
      setImportError('Invalid JSON. Paste the exact output from "Copy peer setup".');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!encryptionKey && !editingId) {
      setSaveError(
        'Encryption key is required. Click "Generate encryption key" to create one.'
      );
      return;
    }

    setSaving(true);
    setSaveError(null);

    const normalizedCarrier = carrier === 'direct' ? '' : carrier;
    const effectiveRemoteIp =
      mode === 'iran'
        ? normalizedCarrier === 'gre' || normalizedCarrier === 'ipip'
          ? carrierRemoteInner
          : remoteIp || carrierPeerIp
        : remoteIp || carrierPeerIp;

    const payload: Partial<TunnelConfig> = {
      id: editingId || undefined,
      name: name || `Tunnel_${protocol.toUpperCase()}_${remotePort}`,
      mode,
      network_profile: networkProfile === 'custom' ? '' : networkProfile,
      protocol,
      carrier: normalizedCarrier,
      local_ports: mode === 'iran' ? localPorts : '',
      remote_ip: effectiveRemoteIp,
      remote_port: Number(remotePort),
      target_host: targetHost || '127.0.0.1',
      target_port: Number(targetPort),
      encryption_key: encryptionKey,
      carrier_peer_ip: carrierPeerIp.trim(),
      carrier_local_ip: carrierLocalIp.trim(),
      carrier_local_inner:
        normalizedCarrier === 'gre' || normalizedCarrier === 'ipip'
          ? carrierLocalInner.trim()
          : '',
      carrier_remote_inner:
        normalizedCarrier === 'gre' || normalizedCarrier === 'ipip'
          ? carrierRemoteInner.trim()
          : '',
      carrier_mtu:
        normalizedCarrier === 'gre' || normalizedCarrier === 'ipip'
          ? Number(carrierMtu) || 1280
          : 0,
      carrier_port:
        normalizedCarrier === 'paqet' ||
        normalizedCarrier === 'xray' ||
        normalizedCarrier === 'hysteria'
          ? Number(carrierPort)
          : 0,
      carrier_auth: carrierAuth,
      carrier_obfs: carrierObfs,
      reality_target: realityTarget.trim(),
      reality_private_key: realityPrivateKey,
      reality_public_key: realityPublicKey.trim(),
      reality_short_id: realityShortId.trim(),
      server_name: serverName.trim(),
      ws_path: wsPath.trim() || '/ws',
      tls_fragment_size: Number(tlsFragmentSize) || 0,
      tls_fragment_delay_ms: Number(tlsFragmentDelayMs) || 0,
      tls_cert_pem: tlsCertPem,
      tls_key_pem: tlsKeyPem,
      tls_ca_pem: tlsCaPem,
      tls_cert_file: tlsCertFile.trim(),
      tls_key_file: tlsKeyFile.trim(),
      tls_ca_file: tlsCaFile.trim(),
      kcp_mode: kcpMode,
      quic_disable_pmtu: quicDisablePmtu,
      listen_address: listenAddress.trim(),
      underlay_interface: underlayInterface.trim(),
      proxy_url: proxyUrl.trim(),
      dial_timeout_seconds: Number(dialTimeoutSeconds) || 0,
      idle_timeout_seconds: Number(idleTimeoutSeconds) || 0,
      fallback_cooldown_seconds: Number(fallbackCooldownSeconds) || 0,
    };

    try {
      await tunnelService.saveTunnel(payload);
      setModalOpen(false);
      showToast('success', `Tunnel "${payload.name}" saved successfully.`);
      await fetchAll();
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
      await fetchAll();
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to start tunnel'));
    }
  };

  const handleStop = async (id: string) => {
    try {
      await tunnelService.stopTunnel(id);
      showToast('success', 'Tunnel stopped.');
      await fetchAll();
    } catch (err) {
      showToast('error', getErrorMessage(err, 'Failed to stop tunnel'));
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await tunnelService.deleteTunnel(id);
      setDeleteConfirmId(null);
      showToast('success', 'Tunnel deleted.');
      await fetchAll();
    } catch (err) {
      setDeleteConfirmId(null);
      showToast('error', getErrorMessage(err, 'Failed to delete tunnel'));
    }
  };

  const formatUptime = (timestamp?: number): string => {
    if (!timestamp) return 'Offline';
    const seconds = Math.floor(Date.now() / 1000) - timestamp;
    if (seconds < 0) return 'Just started';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return hrs > 0 ? `${hrs}h ${mins}m active` : `${mins}m active`;
  };

  const isManagedCarrier =
    carrier === 'gre' ||
    carrier === 'ipip' ||
    carrier === 'paqet' ||
    carrier === 'xray' ||
    carrier === 'hysteria';

  const needsTlsConfig =
    protocol === 'wss' ||
    protocol === 'wss-shaped' ||
    protocol === 'auto' ||
    carrier === 'hysteria';

  return (
    <div className="space-y-6">
      {toast && (
        <div
          className={`fixed top-20 right-4 z-[60] px-4 py-3 rounded-xl shadow-2xl border text-sm font-medium flex items-center gap-2 ${
            toast.type === 'success'
              ? 'bg-primary-500/10 border-primary-500/20 text-primary-400'
              : 'bg-red-500/10 border-red-500/20 text-red-400'
          }`}
        >
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 bg-[#111111]/60 border border-[#222222] rounded-2xl p-6 shadow-xl">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <HardDrive className="w-6 h-6 text-primary-500" />
            Tunnel &amp; Transport Management
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure Bridge (Iran) and Exit (Overseas) reverse tunnels with native
            QUIC/WSS transports or agent-managed Paqet, Xray REALITY, Hysteria 2,
            GRE, and IPIP carriers.
          </p>
          {agentAvailable !== null && (
            <div className="mt-2.5 flex items-center gap-2 text-xs">
              {agentAvailable ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-400 font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Network Agent Connected (Managed Transports Ready)
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-300 font-medium">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  {agentMessage || 'Network Agent offline (Direct QUIC/WSS/TCP/KCP only)'}
                </span>
              )}
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={() => {
              setImportError(null);
              setImportModalOpen(true);
            }}
            className="flex items-center gap-2 px-4 py-2.5 bg-[#1a1a1a] hover:bg-[#242424] text-slate-200 font-semibold rounded-xl border border-[#2a2a2a] transition-all text-sm"
          >
            <Upload className="w-4 h-4 text-primary-400" />
            Import peer setup
          </button>
          <button
            onClick={openAddModal}
            className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-semibold rounded-xl shadow-lg shadow-primary-500/20 transition-all text-sm"
          >
            <Plus className="w-4 h-4 font-bold" />
            Add New Tunnel
          </button>
        </div>
      </div>

      {/* Tunnels Grid */}
      {loading ? (
        <div className="flex justify-center py-12">
          <Activity className="w-8 h-8 animate-spin text-primary-500" />
        </div>
      ) : tunnels.length === 0 ? (
        <div className="text-center py-16 bg-[#111111]/30 border border-[#222222] rounded-2xl">
          <HardDrive className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">
            No tunnels configured yet
          </h3>
          <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
            Create an Overseas node first and click &ldquo;Copy peer setup&rdquo;,
            or click &ldquo;Import peer setup&rdquo; on your Iran server.
          </p>
          <div className="mt-6 flex items-center justify-center gap-3">
            <button
              onClick={openAddModal}
              className="px-4 py-2 bg-primary-500/15 hover:bg-primary-500/25 text-primary-400 font-semibold rounded-xl text-sm transition-colors border border-primary-500/30"
            >
              Add New Tunnel
            </button>
            <button
              onClick={() => setImportModalOpen(true)}
              className="px-4 py-2 bg-[#1a1a1a] hover:bg-slate-800 text-slate-300 font-medium rounded-xl text-sm transition-colors border border-[#222222]"
            >
              Import peer setup
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tunnels.map((t) => {
            const rt = runtimes[t.id];
            const carrierLabel =
              t.carrier && t.carrier !== 'direct'
                ? `${t.carrier.toUpperCase()} + ${t.protocol.toUpperCase()}`
                : t.protocol.toUpperCase();

            return (
              <div
                key={t.id}
                className={`bg-[#111111]/60 border rounded-2xl p-6 shadow-xl relative flex flex-col justify-between transition-all ${
                  t.status === 'active'
                    ? 'border-primary-500/30 shadow-primary-500/5'
                    : 'border-[#222222]'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div
                        className={`w-3 h-3 rounded-full flex-shrink-0 ${
                          t.status === 'active'
                            ? 'bg-primary-500 shadow-lg shadow-primary-500/50'
                            : 'bg-slate-600'
                        }`}
                      />
                      <h3 className="font-bold text-white tracking-tight text-lg truncate">
                        {t.name}
                      </h3>
                    </div>
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                        t.mode === 'iran'
                          ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                          : 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                      }`}
                    >
                      {t.mode}
                    </span>
                  </div>

                  <div className="bg-[#0a0a0a]/60 border border-[#222222] rounded-xl p-3.5 space-y-2 text-xs font-medium text-slate-300">
                    <div className="flex justify-between items-center py-0.5 border-b border-[#222222]/60">
                      <span className="text-slate-500">Transport:</span>
                      <span className="uppercase text-primary-400 font-bold tracking-wide">
                        {carrierLabel}
                      </span>
                    </div>

                    {t.network_profile && (
                      <div className="flex justify-between items-center py-0.5 border-b border-[#222222]/60">
                        <span className="text-slate-500">Profile:</span>
                        <span className="font-mono text-slate-200">
                          {t.network_profile}
                        </span>
                      </div>
                    )}

                    {t.mode === 'iran' ? (
                      <>
                        <div className="flex justify-between items-center py-0.5 border-b border-[#222222]/60">
                          <span className="text-slate-500">Peer Endpoint:</span>
                          <span className="font-mono text-white">
                            {t.carrier_peer_ip || t.remote_ip}:
                            {t.carrier_port || t.remote_port}
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
                            {t.carrier_port
                              ? `${t.carrier_port} -> ${t.remote_port}`
                              : t.remote_port}
                          </span>
                        </div>
                        <div className="flex justify-between items-center py-0.5">
                          <span className="text-slate-500">Target Dest:</span>
                          <span className="font-mono text-primary-300 bg-primary-500/10 px-1.5 py-0.5 rounded border border-primary-500/20">
                            {t.target_host || '127.0.0.1'}:{t.target_port}
                          </span>
                        </div>
                      </>
                    )}

                    {rt && (
                      <div className="flex justify-between items-center py-0.5 border-t border-[#222222]/60">
                        <span className="text-slate-500">Carrier Agent:</span>
                        <span
                          className={`font-semibold uppercase ${
                            rt.state === 'running'
                              ? 'text-primary-400'
                              : 'text-red-400'
                          }`}
                          title={rt.detail || ''}
                        >
                          {rt.state}
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
                <div className="mt-5 pt-4 border-t border-[#222222] flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs text-slate-500 font-mono">
                    {formatUptime(t.uptime)}
                  </div>
                  <div className="flex items-center gap-1.5">
                    {t.mode === 'overseas' && (
                      <button
                        onClick={() => handleCopyPeerSetup(t)}
                        title="Copy peer setup for Iran panel"
                        className="px-2.5 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 font-semibold rounded-lg border border-purple-500/25 flex items-center gap-1 text-xs transition-colors"
                      >
                        <Copy className="w-3.5 h-3.5" />
                        Copy peer setup
                      </button>
                    )}
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
                      title="Edit tunnel"
                    >
                      <Edit className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirmId(t.id)}
                      className="p-1.5 bg-[#1a1a1a] hover:bg-red-500/20 text-slate-400 hover:text-red-400 rounded-lg transition-colors border border-[#222222] hover:border-red-500/30"
                      title="Delete tunnel"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Peer Setup Export Modal */}
      {peerExportJson && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111111] border border-[#222222] rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#222222] pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Copy className="w-5 h-5 text-primary-500" />
                Iran Peer Setup JSON
              </h3>
              <button
                onClick={() => setPeerExportJson(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <p className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-xl p-3">
              {peerExportNotice}
            </p>
            <textarea
              readOnly
              rows={10}
              value={peerExportJson}
              onFocus={(e) => e.currentTarget.select()}
              className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary-500"
            />
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={async () => {
                  const ok = await copyTextWithFallback(peerExportJson);
                  showToast(
                    ok ? 'success' : 'error',
                    ok
                      ? 'Copied to clipboard!'
                      : 'Select the JSON text above and press Ctrl+C / Cmd+C.'
                  );
                }}
                className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-slate-950 font-bold rounded-xl text-sm flex items-center gap-1.5"
              >
                <Copy className="w-4 h-4" />
                Copy JSON
              </button>
              <button
                onClick={() => setPeerExportJson(null)}
                className="px-4 py-2 bg-[#1a1a1a] hover:bg-slate-700 text-slate-300 font-semibold rounded-xl text-sm"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Import Peer Setup Modal */}
      {importModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleApplyPeerSetup}
            className="bg-[#111111] border border-[#222222] rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4"
          >
            <div className="flex items-center justify-between border-b border-[#222222] pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Upload className="w-5 h-5 text-primary-500" />
                Import Peer Setup from Overseas Node
              </h3>
              <button
                type="button"
                onClick={() => setImportModalOpen(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Paste the JSON exported via <strong className="text-white">Copy peer setup</strong> on
              your Overseas panel, then click <strong className="text-white">Apply peer setup</strong>.
            </p>
            {importError && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-3 rounded-xl text-xs">
                {importError}
              </div>
            )}
            <textarea
              required
              rows={9}
              value={importJsonText}
              onChange={(e) => setImportJsonText(e.target.value)}
              placeholder='{"version": 1, "tunnel": { ... }}'
              className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl p-3 text-xs font-mono text-white focus:outline-none focus:border-primary-500"
            />
            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setImportModalOpen(false)}
                className="px-4 py-2 bg-[#1a1a1a] hover:bg-slate-700 text-slate-300 font-semibold rounded-xl text-sm"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-5 py-2 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-slate-950 font-bold rounded-xl text-sm"
              >
                Apply peer setup
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111111] border border-[#222222] rounded-2xl max-w-sm w-full p-6 shadow-2xl">
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
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-sm flex items-start sm:items-center justify-center p-2 sm:p-4 pt-8 sm:pt-4">
          <div className="bg-[#111111] border border-[#222222] rounded-2xl w-full max-w-2xl p-4 sm:p-6 shadow-2xl relative max-h-[92vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[#222222] pb-4 mb-4">
              <h2 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 sm:w-6 sm:h-6 text-primary-500" />
                {editingId ? 'Edit Tunnel Node' : 'Configure Tunnel Node'}
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

            {legacyProtocol && (
              <div className="mb-4 bg-amber-500/10 border border-amber-500/25 text-amber-300 p-3 rounded-xl text-xs">
                Deprecated protocol <code>{legacyProtocol}</code> was migrated to{' '}
                <strong>QUIC</strong>. Review the fields and save to update this tunnel.
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <fieldset disabled={saving} className="space-y-4">
                {/* Name + Role */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Tunnel Node Name
                    </label>
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Frankfurt_Exit_01"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Server Side Role
                    </label>
                    <select
                      value={mode}
                      onChange={(e) =>
                        handleModeChange(e.target.value as 'iran' | 'overseas')
                      }
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500 font-semibold"
                    >
                      <option value="overseas">Overseas (Node / Listener)</option>
                      <option value="iran">Iran (Bridge / Initiator)</option>
                    </select>
                  </div>
                </div>

                {/* Network Profile */}
                <div className="bg-[#0a0a0a]/80 border border-[#222222] rounded-xl p-3.5 space-y-2">
                  <label className="block text-xs font-semibold uppercase tracking-wider text-primary-400">
                    Network Profile Preset
                  </label>
                  <select
                    value={networkProfile}
                    onChange={(e) => applyProfilePreset(e.target.value, mode)}
                    className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3.5 py-2 text-sm text-white font-semibold focus:outline-none focus:border-primary-500"
                  >
                    {profiles.map((p) => (
                      <option key={p.name} value={p.name}>
                        {p.label}
                      </option>
                    ))}
                    <option value="custom">Custom Transport / Carrier</option>
                  </select>
                  <p className="text-[11px] text-slate-400">
                    {profiles.find((p) => p.name === networkProfile)?.summary ||
                      'Manually select the carrier and inner HESAR transport protocol below.'}
                  </p>
                </div>

                {/* Carrier + Inner Protocol */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Outer Carrier
                    </label>
                    <select
                      value={carrier || 'direct'}
                      onChange={(e) => {
                        const next = e.target.value as TunnelCarrier;
                        setCarrier(next);
                        setNetworkProfile('custom');
                        if (next === 'xray' || next === 'hysteria') {
                          setProtocol('tcp');
                        }
                      }}
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-semibold focus:outline-none focus:border-primary-500"
                    >
                      <option value="direct">Direct (Native HESAR Socket)</option>
                      <option value="paqet">Managed Paqet (Raw Packet KCP)</option>
                      <option value="xray">Managed Xray (XHTTP + REALITY)</option>
                      <option value="hysteria">Managed Hysteria 2 (Salamander UDP)</option>
                      <option value="gre">Managed Layer-3 GRE</option>
                      <option value="ipip">Managed Layer-3 IPIP</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Inner HESAR Protocol
                    </label>
                    <select
                      value={protocol}
                      onChange={(e) => {
                        setProtocol(e.target.value as TunnelProtocol);
                        setNetworkProfile('custom');
                      }}
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-bold focus:outline-none focus:border-primary-500"
                    >
                      <option value="auto">AUTO (QUIC with WSS Fallback)</option>
                      <option value="quic">QUIC (TLS 1.3 Multiplexed)</option>
                      <option value="wss">WSS (TLS 1.3 + WebSocket)</option>
                      <option value="wss-shaped">WSS-SHAPED (Padded WebSocket)</option>
                      <option value="tcp">TCP (AEAD Framed)</option>
                      <option value="kcp">KCP (UDP ARQ)</option>
                    </select>
                  </div>
                </div>

                {/* WAN IPv4 & Endpoint Configuration */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      {mode === 'iran'
                        ? 'Overseas Server WAN IPv4 / Host'
                        : 'Other Server WAN IPv4 (Iran IP)'}
                    </label>
                    <input
                      type="text"
                      required={mode === 'iran' || isManagedCarrier}
                      value={mode === 'iran' ? remoteIp : carrierPeerIp}
                      onChange={(e) => {
                        const val = e.target.value;
                        if (mode === 'iran') {
                          setRemoteIp(val);
                          setCarrierPeerIp(val);
                        } else {
                          setCarrierPeerIp(val);
                        }
                      }}
                      placeholder="e.g. 203.0.113.10"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                      Local WAN IPv4 Override (Optional)
                    </label>
                    <input
                      type="text"
                      value={carrierLocalIp}
                      onChange={(e) => setCarrierLocalIp(e.target.value)}
                      placeholder="Auto-detected from route table"
                      className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                    />
                  </div>
                </div>

                {/* Ports Configuration */}
                {mode === 'iran' ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        Local Listen Port(s)
                      </label>
                      <input
                        type="text"
                        required
                        value={localPorts}
                        onChange={(e) => setLocalPorts(e.target.value)}
                        placeholder="18080 or 80,443 or 10000-10010"
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-primary-300 font-mono focus:outline-none focus:border-primary-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        {carrier === 'paqet' ||
                        carrier === 'xray' ||
                        carrier === 'hysteria'
                          ? 'Internal HESAR Port'
                          : 'Overseas Tunnel Port'}
                      </label>
                      <input
                        type="number"
                        required
                        min={1}
                        max={65535}
                        value={remotePort}
                        onChange={(e) => setRemotePort(Number(e.target.value))}
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        {carrier === 'paqet' ||
                        carrier === 'xray' ||
                        carrier === 'hysteria'
                          ? 'Internal Listen Port'
                          : 'Connection Listen Port'}
                      </label>
                      <input
                        type="number"
                        required
                        min={1}
                        max={65535}
                        value={remotePort}
                        onChange={(e) => setRemotePort(Number(e.target.value))}
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        Target Host
                      </label>
                      <input
                        type="text"
                        required
                        value={targetHost}
                        onChange={(e) => setTargetHost(e.target.value)}
                        placeholder="127.0.0.1"
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
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
                        placeholder="8080"
                        className="w-full bg-[#0a0a0a] border border-[#222222] rounded-xl px-3.5 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                      />
                    </div>
                  </div>
                )}

                {/* Encryption Key + One-Click Credential Generator */}
                <div className="bg-[#0a0a0a] border border-[#222222] rounded-xl p-3.5 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Cryptographic Keys &amp; Transport Credentials
                    </label>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleKeygen}
                        className="px-2.5 py-1 bg-[#1a1a1a] hover:bg-[#252525] text-primary-400 rounded-lg border border-[#2a2a2a] text-xs font-semibold flex items-center gap-1"
                      >
                        <Key className="w-3.5 h-3.5" />
                        Generate encryption key
                      </button>
                      <button
                        type="button"
                        disabled={generatingCreds}
                        onClick={handleGenerateTransportCredentials}
                        className="px-2.5 py-1 bg-primary-500/15 hover:bg-primary-500/25 text-primary-300 rounded-lg border border-primary-500/30 text-xs font-semibold flex items-center gap-1 disabled:opacity-50"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                        {generatingCreds
                          ? 'Generating...'
                          : 'Generate transport credentials'}
                      </button>
                    </div>
                  </div>
                  <input
                    type="text"
                    required={!editingId}
                    value={encryptionKey}
                    onChange={(e) => setEncryptionKey(e.target.value)}
                    placeholder="64-character hex or 16+ character shared key"
                    className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3.5 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500"
                  />
                </div>

                {/* Managed GRE / IPIP Fields */}
                {(carrier === 'gre' || carrier === 'ipip') && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl space-y-3">
                    <div className="text-xs font-semibold uppercase tracking-wider text-primary-400 flex items-center gap-1.5">
                      <Server className="w-4 h-4" />
                      Layer-3 {carrier.toUpperCase()} Interface Addressing
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Local Inner IPv4
                        </label>
                        <input
                          type="text"
                          required
                          value={carrierLocalInner}
                          onChange={(e) => setCarrierLocalInner(e.target.value)}
                          placeholder="10.77.0.2"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Remote Inner IPv4
                        </label>
                        <input
                          type="text"
                          required
                          value={carrierRemoteInner}
                          onChange={(e) => setCarrierRemoteInner(e.target.value)}
                          placeholder="10.77.0.1"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Tunnel MTU (576-1500)
                        </label>
                        <input
                          type="number"
                          min={576}
                          max={1500}
                          value={carrierMtu}
                          onChange={(e) => setCarrierMtu(Number(e.target.value))}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Managed Paqet Fields */}
                {carrier === 'paqet' && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl space-y-3">
                    <div className="text-xs font-semibold uppercase tracking-wider text-primary-400">
                      Managed Paqet Raw-Socket KCP Settings
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Dedicated Paqet Port (1024-65535)
                        </label>
                        <input
                          type="number"
                          required
                          min={1024}
                          max={65535}
                          value={carrierPort}
                          onChange={(e) => setCarrierPort(Number(e.target.value))}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Paqet KCP Shared Secret
                        </label>
                        <input
                          type="text"
                          required
                          value={carrierAuth}
                          onChange={(e) => setCarrierAuth(e.target.value)}
                          placeholder="Click Generate transport credentials"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Managed Xray REALITY Fields */}
                {carrier === 'xray' && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl space-y-3">
                    <div className="text-xs font-semibold uppercase tracking-wider text-primary-400">
                      Managed Xray-core (VLESS + XHTTP + REALITY)
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          External REALITY Port
                        </label>
                        <input
                          type="number"
                          required
                          min={1}
                          max={65535}
                          value={carrierPort}
                          onChange={(e) => setCarrierPort(Number(e.target.value))}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          REALITY Cover Server Name
                        </label>
                        <input
                          type="text"
                          required
                          value={serverName}
                          onChange={(e) => setServerName(e.target.value)}
                          placeholder="www.microsoft.com"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Cover Target host:port (Optional)
                        </label>
                        <input
                          type="text"
                          value={realityTarget}
                          onChange={(e) => setRealityTarget(e.target.value)}
                          placeholder="www.microsoft.com:443"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Carrier Auth Secret
                        </label>
                        <input
                          type="text"
                          required
                          value={carrierAuth}
                          onChange={(e) => setCarrierAuth(e.target.value)}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          {mode === 'overseas'
                            ? 'REALITY Private Key'
                            : 'REALITY Public Key'}
                        </label>
                        <input
                          type="text"
                          required
                          value={
                            mode === 'overseas'
                              ? realityPrivateKey
                              : realityPublicKey
                          }
                          onChange={(e) =>
                            mode === 'overseas'
                              ? setRealityPrivateKey(e.target.value)
                              : setRealityPublicKey(e.target.value)
                          }
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          REALITY Short ID (Hex)
                        </label>
                        <input
                          type="text"
                          required
                          value={realityShortId}
                          onChange={(e) => setRealityShortId(e.target.value)}
                          placeholder="8-16 hex chars"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Managed Hysteria 2 Fields */}
                {carrier === 'hysteria' && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl space-y-3">
                    <div className="text-xs font-semibold uppercase tracking-wider text-primary-400">
                      Managed Hysteria 2 (Salamander QUIC Obfuscation)
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Hysteria UDP Port
                        </label>
                        <input
                          type="number"
                          required
                          min={1}
                          max={65535}
                          value={carrierPort}
                          onChange={(e) => setCarrierPort(Number(e.target.value))}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Auth Secret
                        </label>
                        <input
                          type="text"
                          required
                          value={carrierAuth}
                          onChange={(e) => setCarrierAuth(e.target.value)}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Salamander Obfs Secret
                        </label>
                        <input
                          type="text"
                          required
                          value={carrierObfs}
                          onChange={(e) => setCarrierObfs(e.target.value)}
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* TLS / WSS / Hysteria Certificate & Fragmentation Settings */}
                {needsTlsConfig && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl space-y-3">
                    <div className="text-xs font-semibold uppercase tracking-wider text-primary-400">
                      TLS Certificate &amp; WebSocket Obfuscation
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          TLS Server Name (SNI)
                        </label>
                        <input
                          type="text"
                          required={mode === 'iran'}
                          value={serverName}
                          onChange={(e) => setServerName(e.target.value)}
                          placeholder="hesar.internal"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                        />
                      </div>
                      {(protocol === 'wss' ||
                        protocol === 'wss-shaped' ||
                        protocol === 'auto') && (
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            WebSocket Path
                          </label>
                          <input
                            type="text"
                            value={wsPath}
                            onChange={(e) => setWsPath(e.target.value)}
                            placeholder="/ws"
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                      )}
                    </div>

                    {(protocol === 'wss' ||
                      protocol === 'wss-shaped' ||
                      protocol === 'auto') && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            TLS ClientHello Fragment Size (0 = Off, 1-256 B)
                          </label>
                          <input
                            type="number"
                            min={0}
                            max={256}
                            value={tlsFragmentSize}
                            onChange={(e) =>
                              setTlsFragmentSize(Number(e.target.value))
                            }
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            TLS Fragment Delay (0-250 ms)
                          </label>
                          <input
                            type="number"
                            min={0}
                            max={250}
                            value={tlsFragmentDelayMs}
                            onChange={(e) =>
                              setTlsFragmentDelayMs(Number(e.target.value))
                            }
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                      </div>
                    )}

                    {mode === 'overseas' ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            TLS Certificate PEM
                          </label>
                          <textarea
                            rows={3}
                            value={tlsCertPem}
                            onChange={(e) => setTlsCertPem(e.target.value)}
                            placeholder="-----BEGIN CERTIFICATE----- (Click Generate transport credentials)"
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl p-2 text-[11px] text-white font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            TLS Private Key PEM
                          </label>
                          <textarea
                            rows={3}
                            value={tlsKeyPem}
                            onChange={(e) => setTlsKeyPem(e.target.value)}
                            placeholder="-----BEGIN PRIVATE KEY-----"
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl p-2 text-[11px] text-white font-mono"
                          />
                        </div>
                      </div>
                    ) : (
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          Pinned Server CA / Certificate PEM (Exported by Overseas Node)
                        </label>
                        <textarea
                          rows={3}
                          value={tlsCaPem}
                          onChange={(e) => setTlsCaPem(e.target.value)}
                          placeholder="-----BEGIN CERTIFICATE-----"
                          className="w-full bg-[#111111] border border-[#222222] rounded-xl p-2 text-[11px] text-white font-mono"
                        />
                      </div>
                    )}
                  </div>
                )}

                {/* KCP Options */}
                {protocol === 'kcp' && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl space-y-2">
                    <label className="block text-xs font-semibold uppercase tracking-wider text-primary-400 flex items-center gap-1.5">
                      <HelpCircle className="w-4 h-4" /> KCP Stack Mode
                    </label>
                    <select
                      value={kcpMode}
                      onChange={(e) =>
                        setKcpMode(
                          e.target.value as 'normal' | 'fast' | 'fast2' | 'fast3'
                        )
                      }
                      className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-sm text-white focus:outline-none"
                    >
                      <option value="normal">Normal - Bandwidth Optimized</option>
                      <option value="fast">Fast - Quick Recovery</option>
                      <option value="fast2">Fast2 - Low Latency + Recovery</option>
                      <option value="fast3">Fast3 - Extreme Low Latency</option>
                    </select>
                  </div>
                )}

                {/* QUIC MTU Option */}
                {(protocol === 'quic' || protocol === 'auto') && (
                  <div className="bg-[#0a0a0a] border border-[#222222] p-3.5 rounded-xl">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={quicDisablePmtu}
                        onChange={(e) => setQuicDisablePmtu(e.target.checked)}
                        className="accent-primary-500"
                      />
                      <span className="text-xs font-semibold text-slate-300">
                        Disable QUIC Path MTU Discovery (Recommended on GRE/IPIP or lossy UDP links)
                      </span>
                    </label>
                  </div>
                )}

                {/* Advanced Network & Timeouts Accordion */}
                <div className="border border-[#222222] rounded-xl overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    className="w-full px-4 py-2.5 bg-[#0a0a0a] hover:bg-[#141414] flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-400"
                  >
                    <span>Advanced Binding, Proxy &amp; Timeouts</span>
                    {showAdvanced ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </button>
                  {showAdvanced && (
                    <div className="p-3.5 bg-[#0a0a0a]/60 space-y-3 border-t border-[#222222]">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            Bind / Listen IP
                          </label>
                          <input
                            type="text"
                            value={listenAddress}
                            onChange={(e) => setListenAddress(e.target.value)}
                            placeholder="0.0.0.0"
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            Underlay Interface
                          </label>
                          <input
                            type="text"
                            value={underlayInterface}
                            onChange={(e) => setUnderlayInterface(e.target.value)}
                            placeholder="e.g. eth0"
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            Outbound Proxy URL
                          </label>
                          <input
                            type="text"
                            value={proxyUrl}
                            onChange={(e) => setProxyUrl(e.target.value)}
                            placeholder="socks5://127.0.0.1:1080"
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            Dial Timeout (s)
                          </label>
                          <input
                            type="number"
                            min={1}
                            max={120}
                            value={dialTimeoutSeconds}
                            onChange={(e) =>
                              setDialTimeoutSeconds(Number(e.target.value))
                            }
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            Idle Timeout (s)
                          </label>
                          <input
                            type="number"
                            min={5}
                            max={600}
                            value={idleTimeoutSeconds}
                            onChange={(e) =>
                              setIdleTimeoutSeconds(Number(e.target.value))
                            }
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">
                            Auto Fallback Cooldown (s)
                          </label>
                          <input
                            type="number"
                            min={5}
                            max={3600}
                            value={fallbackCooldownSeconds}
                            onChange={(e) =>
                              setFallbackCooldownSeconds(Number(e.target.value))
                            }
                            className="w-full bg-[#111111] border border-[#222222] rounded-xl px-3 py-2 text-xs text-white font-mono"
                          />
                        </div>
                      </div>
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
