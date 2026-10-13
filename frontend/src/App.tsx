import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Route, Routes, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { ProtectedRoute } from './components/ProtectedRoute';

// ✅ Lazy loading — بیلد کوچک‌تر و سریع‌تر
const Login = lazy(() =>
  import('./pages/Login').then((m) => ({ default: m.Login }))
);
const Dashboard = lazy(() =>
  import('./pages/Dashboard').then((m) => ({ default: m.Dashboard }))
);
const Tunnels = lazy(() =>
  import('./pages/Tunnels').then((m) => ({ default: m.Tunnels }))
);
const Logs = lazy(() =>
  import('./pages/Logs').then((m) => ({ default: m.Logs }))
);
const Settings = lazy(() =>
  import('./pages/Settings').then((m) => ({ default: m.Settings }))
);
const Tester = lazy(() =>
  import('./pages/Tester').then((m) => ({ default: m.Tester }))
);

const LoadingSpinner: React.FC = () => (
  <div className="flex items-center justify-center h-[60vh]">
    <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500" />
  </div>
);

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingSpinner />}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <div className="min-h-full bg-[#0a0a0a] text-slate-100 flex flex-col">
                  <Navbar />
                  <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/tunnels" element={<Tunnels />} />
                      <Route path="/logs" element={<Logs />} />
                      <Route path="/tester" element={<Tester />} />
                      <Route path="/settings" element={<Settings />} />
                      <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                  </main>
                </div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
};

export default App;