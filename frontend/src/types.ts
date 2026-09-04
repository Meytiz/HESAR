export interface TunnelConfig {
  id: string;
  name: string;
  mode: 'iran' | 'overseas';
  /**
   * vNext transports:
   *  - quic: primary. TCP→QUIC streams over one multiplexed connection
   *          (+ optional experimental UDP relay via QUIC DATAGRAM).
   *  - tls:  TLS 1.3-over-TCP fallback used when UDP/QUIC is filtered.
   *  - tcp:  legacy custom AEAD transport (kept for compatibility).
   *  - kcp:  legacy/experimental reliable-UDP transport.
   * 'sni_spoof' and 'ip_spoof' were REMOVED in vNext.
   */
  protocol: 'tcp' | 'kcp' | 'quic' | 'tls';
  status: 'active' | 'inactive';
  local_ports: string;
  remote_ip: string;
  remote_port: number;
  encryption_key: string;
  target_port: number;
  kcp_mode: 'normal' | 'fast' | 'fast2' | 'fast3';
  /** Experimental: relay UDP through QUIC DATAGRAM (quic tunnels only). */
  quic_enable_udp?: boolean;
  bytes_in: number;
  bytes_out: number;
  /** Unix timestamp (seconds) when tunnel started, 0 if inactive */
  uptime: number;
}

export interface SystemStats {
  total_tunnels: number;
  active_tunnels: number;
  inactive_tunnels: number;
  cpu_usage: number;
  memory_total: number;
  memory_used: number;
  memory_usage: number;
  load_avg_1: number;
  bbr_active: boolean;
  panel_uptime: number;
}

export interface AppConfig {
  admin_username: string;
  listen_port: number;
  log_path: string;
  log_max_size_mb: number;
  tunnel_count: number;
}

export interface LogMessage {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  message: string;
}

export interface TestResult {
  success: boolean;
  latency_ms: number;
  details: string;
}
