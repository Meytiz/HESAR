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

    // ✅ بررسی واقعی از سرور: /auth/verify is JWT-protected, so this answers
    // 200 only while the stored token is still valid and unrevoked.
    // (It used to call the PUBLIC /auth/status, which always answers 200 —
    // so any leftover token string, expired or revoked alike, unlocked the
    // whole panel UI until the first real API call failed behind it.)
    authService
      .verifySession()
      .then((state) => {
        if (!mounted) return;
        if (state === 'valid') {
          setValid(true);
          return;
        }
        if (state === 'invalid') sessionStorage.removeItem('hesar_token');
        setValid(false);
      })
      .catch(() => {
        if (mounted) setValid(false);
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