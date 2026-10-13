import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, Key, ArrowRight, Activity } from 'lucide-react';
import { authService } from '../services/api';

export const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await authService.login(username, password);
      navigate('/');
    } catch (err: unknown) {
      let msg = 'Invalid username or password';
      if (err && typeof err === 'object' && 'response' in err) {
        const r = err as { response?: { data?: unknown } };
        const d = r.response?.data;
        if (typeof d === 'string') msg = d;
        else if (d && typeof d === 'object') {
          const o = d as Record<string, unknown>;
          if (typeof o.error === 'string') msg = o.error;
          else if (typeof o.message === 'string') msg = o.message;
        }
      } else if (err instanceof Error) {
        msg = err.message;
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] flex flex-col justify-center py-12 sm:px-6 lg:px-8 relative overflow-hidden">
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-primary-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-primary-600 to-primary-400 flex items-center justify-center shadow-xl shadow-primary-500/20 mx-auto">
          <Shield className="w-10 h-10 text-slate-950" />
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-white tracking-tight">HESAR Engine Portal</h2>
        <p className="mt-2 text-center text-sm text-slate-400">Anti-DPI Reverse Tunnel Management Suite</p>
      </div>
      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md relative z-10">
        <div className="bg-[#111111]/80 backdrop-blur-xl py-8 px-4 shadow-2xl sm:rounded-3xl sm:px-10 border border-[#222222]">
          {error && (
            <div className="mb-6 bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-xl text-sm flex items-center gap-2.5 font-medium">
              <Lock className="w-4 h-4 text-red-500 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
          <form onSubmit={handleLogin} autoComplete="on">
            <fieldset disabled={loading}>
              <div className="space-y-6">
                <div>
                  <label htmlFor="username" className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <User className="w-4 h-4 text-primary-400" />
                    Admin Username
                  </label>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    required
                    autoFocus
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                    className="appearance-none block w-full px-4 py-3 bg-[#0a0a0a] border border-[#222222] rounded-xl text-white placeholder-slate-600 focus:outline-none focus:border-primary-500 text-sm font-semibold"
                  />
                </div>
                <div>
                  <label htmlFor="password" className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                    <Key className="w-4 h-4 text-primary-400" />
                    Password
                  </label>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    required
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                    className="appearance-none block w-full px-4 py-3 bg-[#0a0a0a] border border-[#222222] rounded-xl text-white placeholder-slate-600 focus:outline-none focus:border-primary-500 text-sm font-mono"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full flex justify-center items-center gap-2 py-3.5 px-4 rounded-xl shadow-lg shadow-primary-500/20 text-sm font-bold text-slate-950 bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {loading ? <Activity className="w-5 h-5 animate-spin" /> : <ArrowRight className="w-5 h-5" />}
                  {loading ? 'Authenticating...' : 'Access Portal'}
                </button>
              </div>
            </fieldset>
          </form>
          <div className="mt-8 pt-6 border-t border-[#222222] text-center">
            <p className="text-xs text-slate-500 font-mono">Secure tunnel management operations panel.</p>
          </div>
        </div>
      </div>
    </div>
  );
};