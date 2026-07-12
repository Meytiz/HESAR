export interface TunnelConfig {
  id: string;
  name: string;
  mode: 'iran' | 'overseas';
  protocol: 'kcp' | 'tcp' | 'ip_spoof' | 'sni_spoof';
  status: 'active' | 'inactive';
  local_ports: string;
  remote_ip: string;
  remote_port: number;
  encryption_key: string;
  target_port: number;
  kcp_mode: 'normal' | 'fast' | 'fast2' | 'fast3';
  spoof_sni: string;
  fake_ip: string;
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