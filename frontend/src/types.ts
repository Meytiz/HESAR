export type TunnelProtocol =
  | 'quic'
  | 'tcp'
  | 'kcp'
  | 'wss'
  | 'wss-shaped'
  | 'auto';

export type TunnelCarrier =
  | ''
  | 'direct'
  | 'gre'
  | 'ipip'
  | 'paqet'
  | 'xray'
  | 'hysteria';

export interface TunnelConfig {
  id: string;
  name: string;
  mode: 'iran' | 'overseas';
  protocol: TunnelProtocol;
  carrier?: TunnelCarrier;
  network_profile?: string;
  local_ports: string;
  listen_address?: string;
  underlay_interface?: string;
  proxy_url?: string;
  remote_ip: string;
  remote_port: number;
  carrier_peer_ip?: string;
  carrier_local_ip?: string;
  carrier_local_inner?: string;
  carrier_remote_inner?: string;
  carrier_mtu?: number;
  carrier_port?: number;
  carrier_auth?: string;
  carrier_obfs?: string;
  reality_target?: string;
  reality_private_key?: string;
  reality_public_key?: string;
  reality_short_id?: string;
  encryption_key: string;
  target_host?: string;
  target_port: number;
  status: 'active' | 'inactive' | 'error';
  kcp_mode?: 'normal' | 'fast' | 'fast2' | 'fast3';
  quic_enable_udp?: boolean;
  quic_disable_pmtu?: boolean;
  server_name?: string;
  tls_cert_file?: string;
  tls_key_file?: string;
  tls_ca_file?: string;
  tls_cert_pem?: string;
  tls_key_pem?: string;
  tls_ca_pem?: string;
  tls_fragment_size?: number;
  tls_fragment_delay_ms?: number;
  ws_path?: string;
  dial_timeout_seconds?: number;
  idle_timeout_seconds?: number;
  fallback_cooldown_seconds?: number;
  bytes_in?: number;
  bytes_out?: number;
  uptime?: number;
}

export interface NetworkProfile {
  name: string;
  label: string;
  summary: string;
  recommended_protocol: TunnelProtocol;
  carrier?: TunnelCarrier;
}

export interface NetworkRuntimeItem {
  id: string;
  carrier: string;
  role: string;
  state: string;
  detail?: string;
  local_endpoint?: string;
  updated_at?: number;
}

export interface NetworkRuntimeResponse {
  available?: boolean;
  ok?: boolean;
  runtimes?: NetworkRuntimeItem[];
  message?: string;
}

export interface GeneratedTransportKeys {
  carrier_auth: string;
  carrier_obfs: string;
  reality_private_key: string;
  reality_public_key: string;
  reality_short_id: string;
  tls_cert_pem: string;
  tls_key_pem: string;
  server_name: string;
}

export interface PeerSetupExport {
  version: number;
  tunnel: TunnelConfig;
  notice?: string;
}

export interface SystemStats {
  cpu_usage: number;
  memory_usage: number;
  memory_total: number;
  memory_used: number;
  net_rx_bytes: number;
  net_tx_bytes: number;
  active_tunnels: number;
}

export interface AppConfig {
  admin_username: string;
  admin_password?: string;
  log_path: string;
  log_max_size_mb: number;
  allowed_origins?: string[];
}

export interface TestResult {
  success: boolean;
  latency_ms: number;
  details: string;
}

export interface LogMessage {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  message: string;
}
