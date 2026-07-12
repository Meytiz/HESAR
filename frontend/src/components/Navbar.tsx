import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Shield, Activity, HardDrive, FileText, Settings, LogOut, Radio,
} from 'lucide-react';
import { authService } from '../services/api';

// ✅ ورژن در زمان بیلد سوزانده می‌شود — نیازی به API نیست
const APP_VERSION = import.meta.env.VITE_APP_VERSION || 'dev';

export const Navbar: React.FC = () => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await authService.logout();
    } catch {
      sessionStorage.removeItem('hesar_token');
    }
    navigate('/login');
  };

  const navClasses = ({ isActive }: { isActive: boolean }) =>
    `flex items-center px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
      isActive
        ? 'bg-primary-500/10 text-primary-400 border border-primary-500/20'
        : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a1a1a]'
    }`;

  return (
    <header className="sticky top-0 z-50 bg-[#0a0a0a]/80 backdrop-blur-md border-b border-[#222222]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-primary-600 to-primary-400 flex items-center justify-center">
              <Shield className="w-6 h-6 text-slate-950" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  HESAR
                </span>
                {/* ✅ ورژن از بیلد — بدون API call */}
                <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-primary-500/10 text-primary-400 border border-primary-500/20">
                  {APP_VERSION}
                </span>
              </div>
              <p className="text-xs text-slate-500 hidden sm:block">
                Anti-DPI Tunnel Suite
              </p>
            </div>
          </div>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center space-x-1.5">
            <NavLink to="/" end className={navClasses}>
              <Activity className="w-4 h-4 mr-2" /> Dashboard
            </NavLink>
            <NavLink to="/tunnels" className={navClasses}>
              <HardDrive className="w-4 h-4 mr-2" /> Tunnels
            </NavLink>
            <NavLink to="/logs" className={navClasses}>
              <FileText className="w-4 h-4 mr-2" /> Logs
            </NavLink>
            <NavLink to="/tester" className={navClasses}>
              <Radio className="w-4 h-4 mr-2" /> Tester
            </NavLink>
            <NavLink to="/settings" className={navClasses}>
              <Settings className="w-4 h-4 mr-2" /> Settings
            </NavLink>
          </nav>

          {/* Right Actions */}
          <div className="flex items-center space-x-3">
            <a
              href="https://github.com/Meytiz/HESAR"
              target="_blank"
              rel="noopener noreferrer"
              className="p-2 text-slate-400 hover:text-white hover:bg-[#1a1a1a] rounded-lg border border-[#222222] flex items-center space-x-1.5"
            >
              <svg className="w-5 h-5 fill-current" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12Z" />
              </svg>
              <span className="text-xs font-semibold hidden sm:inline">GitHub</span>
            </a>
            <button
              onClick={handleLogout}
              className="flex items-center px-3 py-2 text-sm font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg border border-red-500/20"
            >
              <LogOut className="w-4 h-4 sm:mr-1.5" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>

        {/* Mobile Nav */}
        <div className="flex md:hidden overflow-x-auto py-2 space-x-1 border-t border-[#222222]">
          <NavLink to="/" end className={navClasses}>Dashboard</NavLink>
          <NavLink to="/tunnels" className={navClasses}>Tunnels</NavLink>
          <NavLink to="/logs" className={navClasses}>Logs</NavLink>
          <NavLink to="/tester" className={navClasses}>Tester</NavLink>
          <NavLink to="/settings" className={navClasses}>Settings</NavLink>
        </div>
      </div>
    </header>
  );
};