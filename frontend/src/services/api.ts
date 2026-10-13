import {
  TunnelConfig,
  SystemStats,
  AppConfig,
  TestResult,
  LogMessage,
  NetworkProfile,
  NetworkRuntimeResponse,
  GeneratedTransportKeys,
  PeerSetupExport,
} from '../types';

const TOKEN_STORAGE_KEY = 'hesar_token';

export const getAuthToken = (): string | null => {
  return (
    sessionStorage.getItem(TOKEN_STORAGE_KEY) ||
    localStorage.getItem(TOKEN_STORAGE_KEY)
  );
};

export const setAuthToken = (token: string): void => {
  sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  localStorage.removeItem(TOKEN_STORAGE_KEY);
};

export const clearAuthToken = (): void => {
  sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  localStorage.removeItem(TOKEN_STORAGE_KEY);
};

interface ApiError extends Error {
  response?: {
    status: number;
    data: unknown;
  };
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const res = await fetch(`/api${endpoint}`, {
      ...options,
      headers,
      signal: controller.signal,
    });

    const contentType = res.headers.get('content-type') || '';
    let data: unknown = null;
    if (res.status !== 204) {
      const text = await res.text();
      if (text) {
        if (
          contentType.includes('application/json') ||
          text.startsWith('{') ||
          text.startsWith('[')
        ) {
          try {
            data = JSON.parse(text);
          } catch {
            data = text;
          }
        } else {
          data = text;
        }
      }
    }

    if (res.status === 401 && !endpoint.includes('/login')) {
      clearAuthToken();
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }

    if (!res.ok) {
      let message = `Request failed (${res.status})`;
      if (typeof data === 'string' && data.trim()) {
        message = data.trim();
      } else if (data && typeof data === 'object') {
        const obj = data as Record<string, unknown>;
        if (typeof obj.error === 'string') message = obj.error;
        else if (typeof obj.message === 'string') message = obj.message;
      }
      const err = new Error(message) as ApiError;
      err.response = { status: res.status, data };
      throw err;
    }

    return data as T;
  } finally {
    clearTimeout(timeoutId);
  }
}

export const authService = {
  isAuthenticated: (): boolean => Boolean(getAuthToken()),

  verifySession: async (): Promise<'valid' | 'invalid'> => {
    if (!getAuthToken()) return 'invalid';
    try {
      await apiRequest('/auth/verify');
      return 'valid';
    } catch {
      return 'invalid';
    }
  },

  login: async (username: string, password: string): Promise<string> => {
    const res = await apiRequest<{ token: string }>('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    if (res?.token) {
      setAuthToken(res.token);
    }
    return res.token;
  },

  logout: async (): Promise<void> => {
    try {
      await apiRequest('/logout', { method: 'POST', body: JSON.stringify({}) });
    } catch {
      // Ignore network errors during logout
    } finally {
      clearAuthToken();
    }
  },
};

export const statsService = {
  getStats: async (): Promise<SystemStats> => {
    return apiRequest<SystemStats>('/stats');
  },

  optimize: async (): Promise<{
    status: string;
    message: string;
    warnings?: string[];
  }> => {
    return apiRequest<{ status: string; message: string; warnings?: string[] }>(
      '/optimize',
      {
        method: 'POST',
        body: JSON.stringify({}),
      }
    );
  },
};

export const tunnelService = {
  getTunnels: async (): Promise<TunnelConfig[]> => {
    return apiRequest<TunnelConfig[]>('/tunnels');
  },

  saveTunnel: async (tunnel: Partial<TunnelConfig>): Promise<TunnelConfig> => {
    if (tunnel.id) {
      return apiRequest<TunnelConfig>(`/tunnels/${tunnel.id}`, {
        method: 'PUT',
        body: JSON.stringify(tunnel),
      });
    }
    return apiRequest<TunnelConfig>('/tunnels', {
      method: 'POST',
      body: JSON.stringify(tunnel),
    });
  },

  deleteTunnel: async (id: string): Promise<void> => {
    await apiRequest(`/tunnels/${id}`, { method: 'DELETE' });
  },

  startTunnel: async (id: string): Promise<void> => {
    await apiRequest(`/tunnels/${id}/start`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  },

  stopTunnel: async (id: string): Promise<void> => {
    await apiRequest(`/tunnels/${id}/stop`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  },
};

export const networkService = {
  getProfiles: async (): Promise<NetworkProfile[]> => {
    return apiRequest<NetworkProfile[]>('/network/profiles');
  },

  getRuntime: async (): Promise<NetworkRuntimeResponse> => {
    return apiRequest<NetworkRuntimeResponse>('/network/runtime');
  },

  generateKeys: async (serverName?: string): Promise<GeneratedTransportKeys> => {
    return apiRequest<GeneratedTransportKeys>('/network/keys', {
      method: 'POST',
      body: JSON.stringify({ server_name: serverName || '' }),
    });
  },

  exportPeerConfig: async (id: string): Promise<PeerSetupExport> => {
    return apiRequest<PeerSetupExport>('/network/peer-config', {
      method: 'POST',
      body: JSON.stringify({ id }),
    });
  },
};

export const configService = {
  getConfig: async (): Promise<AppConfig> => {
    return apiRequest<AppConfig>('/config');
  },

  updateConfig: async (config: Partial<AppConfig>): Promise<void> => {
    await apiRequest('/config', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  },
};

export const toolService = {
  keygen: async (): Promise<{ encryption_key: string }> => {
    return apiRequest<{ encryption_key: string }>('/keygen');
  },

  testTCP: async (target_ip: string, port: number): Promise<TestResult> => {
    return apiRequest<TestResult>('/test/tcp', {
      method: 'POST',
      body: JSON.stringify({ target_ip, port }),
    });
  },

  testTLS: async (
    target_ip: string,
    port: number,
    server_name: string
  ): Promise<TestResult> => {
    return apiRequest<TestResult>('/test/tls', {
      method: 'POST',
      body: JSON.stringify({ target_ip, port, server_name }),
    });
  },

  testQUIC: async (target_ip: string, port: number): Promise<TestResult> => {
    return apiRequest<TestResult>('/test/quic', {
      method: 'POST',
      body: JSON.stringify({ target_ip, port }),
    });
  },
};

const fetchWsTicket = async (): Promise<string | null> => {
  try {
    const res = await apiRequest<{ ticket: string }>('/ws-ticket', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    return res?.ticket || null;
  } catch {
    return null;
  }
};

export const createLogWebSocket = (
  onMessage: (log: LogMessage) => void,
  onError?: (err: Event) => void
): (() => void) => {
  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  const connect = async () => {
    if (closed) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;

    const ticket = await fetchWsTicket();
    if (closed) return;
    if (!ticket) {
      if (getAuthToken()) {
        reconnectTimer = setTimeout(() => {
          void connect();
        }, 3000);
      }
      return;
    }

    const url = `${protocol}//${host}/api/logs?ticket=${encodeURIComponent(ticket)}`;

    try {
      ws = new WebSocket(url);

      ws.onmessage = (event) => {
        try {
          const parsed: LogMessage = JSON.parse(event.data);
          onMessage(parsed);
        } catch {
          // Ignore malformed log frame
        }
      };

      ws.onerror = (err) => {
        onError?.(err);
      };

      ws.onclose = () => {
        if (!closed) {
          reconnectTimer = setTimeout(() => {
            void connect();
          }, 3000);
        }
      };
    } catch {
      if (!closed) {
        reconnectTimer = setTimeout(() => {
          void connect();
        }, 5000);
      }
    }
  };

  void connect();

  return () => {
    closed = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (ws) {
      ws.onclose = null;
      ws.close();
    }
  };
};
