import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './lib/AuthContext.jsx';
import Home from './pages/Home.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Projects from './pages/Projects.jsx';
import Scan from './pages/Scan.jsx';
import Vulnerabilities from './pages/Vulnerabilities.jsx';
import Settings from './pages/Settings.jsx';
import ClientPortal from './pages/ClientPortal.jsx';
import Subscription from './pages/Subscription.jsx';
import AIChatWidget from './components/AIChatWidget.jsx';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black text-white">
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-white/30 border-t-white rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

export default function App() {
  const { user, loading } = useAuth();
  const isClient = user?.role === 'client';
  const defaultPath = user ? '/service' : '/';

  return (
    <>
      <div className="fixed inset-0 -z-20 bg-gradient-to-br from-zinc-950 via-zinc-900 to-black animate-mesh-gradient"></div>
      <div className="animated-bg"></div>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/subscription" element={<Subscription />} />
        <Route
          path="/login"
          element={
            !loading && user ? <Navigate to="/service" replace /> : <Login />
          }
        />
        {isClient ? (
          <>
            <Route path="/service" element={<ProtectedRoute><ClientPortal /></ProtectedRoute>} />
            <Route path="*" element={<Navigate to={defaultPath} replace />} />
          </>
        ) : (
          <>
            <Route path="/service" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
            <Route path="/projects" element={<ProtectedRoute><Projects /></ProtectedRoute>} />
            <Route path="/scan" element={<ProtectedRoute><Scan /></ProtectedRoute>} />
            <Route path="/vulnerabilities" element={<ProtectedRoute><Vulnerabilities /></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
            <Route path="*" element={<Navigate to={defaultPath} replace />} />
          </>
        )}
      </Routes>
      {/* Global AI Chat Widget — visible for all authenticated users */}
      {user && <AIChatWidget />}
    </>
  );
}
