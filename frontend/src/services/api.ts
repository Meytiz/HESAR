import axios, { AxiosError } from 'axios';
import type {
  AppConfig,
  SystemStats,
  TestResult,
  TunnelConfig,
  LogMessage,
} from '../types';

// ──────────────────────────────────────────────────
// Axios Instance
// ──────────────────────────────────────────────────

const api = axios.create({
  baseURL: '/api',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ──────────────────────────────────────────────────
// Navigation helper (for 401 redirect without reload)
// ──────────────────────────────────────────────────

let navigateFunction: ((path: string) => void) | null = null;

export const setNavigateFunction = (fn: (path: string) => void) => {
  navigateFunction = fn;
};

// ──────────────────────────────────────────────────
// Interceptors
// ──────────────────────────────────────────────────

api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('hesar_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (
      error.response?.status === 401 &&
      window.location.pathname !== '/login'
    ) {
      sessionStorage.removeItem('hesar_token');
      if (navigateFunction) {
        navigateFunction('/login');
      } else {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ──────────────────────────────────────────────────
// Auth
// ──────────────────────────────────────────────────

export const authService = {
  login: async (username: string, password: string) => {
    const res = await api.post('/auth/login', { username, password });
    if (res.data?.token) {
      sessionStorage.setItem('hesar_token', res.data.token);
    }
    return res.data;
  },

  logout: async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      sessionStorage.removeItem('hesar_token');
    }
  },

  checkStatus: async () => {
    const res = await api.get('/auth/status');
    return res.data;
  },

  isAuthenticated: (): boolean => {
    return !!sessionStorage.getItem('hesar_token');
  },
};

// ──────────────────────────────────────────────────
// Stats
// ──────────────────────────────────────────────────

export const statsService = {
  getStats: async (): Promise<SystemStats> => {
    const res = await api.get('/stats');
    return res.data;
  },
  optimize: async (): Promise<{ success: boolean; bbr_active: boolean; message: string }> => {
    const res = await api.post('/optimize');
    return res.data;
  },
};

// ──────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────

export const configService = {
  getConfig: async (): Promise<AppConfig> => {
    const res = await api.get('/config');
    return res.data;
  },

  updateConfig: async (config: {
    admin_username?: string;
    admin_password?: string;
    log_path?: string;
    log_max_size_mb?: number;
  }) => {
    const res = await api.post('/config', config);
    return res.data;
  },
};

// ──────────────────────────────────────────────────
// Tunnels
// ──────────────────────────────────────────────────

export const tunnelService = {
  getTunnels: async (): Promise<TunnelConfig[]> => {
    const res = await api.get('/tunnels');
    return res.data;
  },

  saveTunnel: async (
    tunnel: Partial<TunnelConfig>
  ): Promise<TunnelConfig> => {
    const res = await api.post('/tunnels', tunnel);
    return res.data;
  },

  deleteTunnel: async (id: string): Promise<void> => {
    await api.delete(`/tunnels/${id}`);
  },

  startTunnel: async (id: string) => {
    const res = await api.post(`/tunnels/${id}/start`);
    return res.data;
  },

  stopTunnel: async (id: string) => {
    const res = await api.post(`/tunnels/${id}/stop`);
    return res.data;
  },
};

// ──────────────────────────────────────────────────
// Tools
// ──────────────────────────────────────────────────

export const toolService = {
  keygen: async (): Promise<{
    noise_private_key: string;
    noise_public_key: string;
    encryption_key: string;
  }> => {
    const res = await api.post('/keygen');
    return res.data;
  },

  testSNI: async (
    target_ip: string,
    port: number,
    sni: string
  ): Promise<TestResult> => {
    const res = await api.post('/tester/sni', { target_ip, port, sni });
    return res.data;
  },

  testIP: async (
    target_ip: string,
    port: number,
    fake_ip: string
  ): Promise<TestResult> => {
    const res = await api.post('/tester/ip', { target_ip, port, fake_ip });
    return res.data;
  },
};

// ──────────────────────────────────────────────────
// WebSocket Log Stream — ✅ auto-reconnect
// ──────────────────────────────────────────────────

export const createLogWebSocket = (
  token: string,
  onMessage: (msg: LogMessage) => void,
  onError?: (err: Event) => void
): (() => void) => {
  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;

  const connect = () => {
    if (disposed) return;

    const protocol =
      window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/api/logs?token=${encodeURIComponent(token)}`;

    ws = new WebSocket(url);

    ws.onopen = () => {
      console.log('[HESAR] Log stream connected');
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as LogMessage;
        onMessage(msg);
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      if (!disposed) {
        console.log(
          '[HESAR] Log stream disconnected. Reconnecting in 3s...'
        );
        reconnectTimer = setTimeout(connect, 3000);
      }
    };

    ws.onerror = (err) => {
      onError?.(err);
      ws?.close();
    };
  };

  connect();

  // ✅ cleanup function
  return () => {
    disposed = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
    }
  };
};