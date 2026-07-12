import React, { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { authService } from '../services/api';

export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [checking, setChecking] = useState(true);
  const [valid, setValid] = useState(false);

  useEffect(() => {
    // ✅ اگر اصلاً token نیست، نیازی به API call نیست
    if (!authService.isAuthenticated()) {
      setValid(false);
      setChecking(false);
      return;
    }

    let mounted = true;

    // ✅ بررسی واقعی از سرور
    authService
      .checkStatus()
      .then(() => {
        if (mounted) setValid(true);
      })
      .catch(() => {
        if (mounted) {
          sessionStorage.removeItem('hesar_token');
          setValid(false);
        }
      })
      .finally(() => {
        if (mounted) setChecking(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  if (checking) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#0a0a0a]">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500" />
          <p className="text-sm text-slate-500 font-medium">
            Verifying authentication...
          </p>
        </div>
      </div>
    );
  }

  if (!valid) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};