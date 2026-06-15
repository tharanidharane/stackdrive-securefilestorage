import { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ToastProvider, useToast } from './components/Toast';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import Dashboard from './pages/Dashboard';
import UploadPage from './pages/UploadPage';
import FileHistory from './pages/FileHistory';
import SecurityPage from './pages/SecurityPage';
import SettingsPage from './pages/SettingsPage';
import LogoutPage from './pages/LogoutPage';
import ShareLanding from './pages/ShareLanding';
import SharedFiles from './pages/SharedFiles';
import GoogleCallback from './pages/GoogleCallback';
import api from './services/api';

const pageTitles = {
  '/overview': { title: 'Dashboard', subtitle: 'Overview of your security posture' },
  '/upload': { title: 'Upload', subtitle: 'Secure file ingestion' },
  '/history': { title: 'File History', subtitle: 'All uploaded files' },
  '/shares': { title: 'Shared Files', subtitle: 'Manage secure share links & access logs' },
  '/security': { title: 'Security', subtitle: 'Pipeline performance & threats' },
  '/settings': { title: 'Settings', subtitle: 'Account & AWS configuration' },
};

function AuthenticatedApp({ user, setUser, onLogout, onFinishLogout }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showRecoveryBanner, setShowRecoveryBanner] = useState(
    localStorage.getItem('recovery_banner_active') === 'true'
  );

  // Fetch notification count
  useEffect(() => {
    const fetchNotifs = async () => {
      try {
        const data = await api.getNotifications();
        setUnreadCount(data.unread_count || 0);
      } catch (e) { /* ignore */ }
    };
    fetchNotifs();
    const interval = setInterval(fetchNotifs, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleStorageChange = () => {
      setShowRecoveryBanner(localStorage.getItem('recovery_banner_active') === 'true');
    };
    window.addEventListener('storage', handleStorageChange);
    // Listen to local custom storage events too
    window.addEventListener('recovery_banner_update', handleStorageChange);
    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('recovery_banner_update', handleStorageChange);
    };
  }, []);

  const handleDismissBanner = () => {
    localStorage.removeItem('recovery_banner_active');
    setShowRecoveryBanner(false);
  };

  const handleUpdateUser = (updatedUser) => {
    setUser(updatedUser);
    // Persist to localStorage for session restore
    const session = JSON.parse(localStorage.getItem('stackdrive_session') || '{}');
    session.user = updatedUser;
    localStorage.setItem('stackdrive_session', JSON.stringify(session));
  };

  return (
    <div className="app-layout">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      <div className={`main-wrapper ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        {showRecoveryBanner && (
          <div style={{
            background: 'linear-gradient(90deg, #7f1d1d 0%, #b91c1c 100%)',
            color: 'white',
            padding: '12px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.9rem',
            fontWeight: '500',
            borderBottom: '1px solid rgba(248, 113, 113, 0.2)',
            zIndex: 100,
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.1rem' }}>⚠️</span>
              <span>This file failed cryptographic verification and may be corrupted or unsafe.</span>
            </div>
            <button 
              onClick={handleDismissBanner}
              style={{
                background: 'none',
                border: 'none',
                color: 'rgba(255, 255, 255, 0.8)',
                cursor: 'pointer',
                fontSize: '1.2rem',
                fontWeight: 'bold',
                padding: '0 8px',
                outline: 'none',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              ×
            </button>
          </div>
        )}
        <HeaderWithTitle unreadCount={unreadCount} email={user?.email} onMarkAllRead={() => setUnreadCount(0)} onLogout={onLogout} />
        <div className="main-content">
          <Routes>
            <Route path="/overview" element={<Dashboard user={user} />} />
            <Route path="/upload" element={<UploadPage user={user} />} />
            <Route path="/history" element={<FileHistory />} />
            <Route path="/shares" element={<SharedFiles />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/settings" element={
              <SettingsPage
                user={user}
                onUpdateUser={handleUpdateUser}
                onLogout={onLogout}
              />
            } />
            <Route path="/logout-transition" element={<LogoutPage onFinishLogout={onFinishLogout} />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

function HeaderWithTitle({ unreadCount, email, onMarkAllRead, onLogout }) {
  const location = useLocation();
  const pageInfo = pageTitles[location.pathname] || { title: 'StackDrive', subtitle: '' };
  return <Header title={pageInfo.title} subtitle={pageInfo.subtitle}
                 unreadCount={unreadCount} email={email} onMarkAllRead={onMarkAllRead} onLogout={onLogout} />;
}

function AppContent() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isLoggingOutState, setIsLoggingOutState] = useState(false);
  const navigate = useNavigate();

  // Restore session on mount
  useEffect(() => {
    const restoreSession = async () => {
      const token = api.getToken();
      if (token) {
        try {
          const data = await api.getMe();
          setUser(data.user);
          localStorage.setItem('stackdrive_session', JSON.stringify({ user: data.user }));
        } catch (e) {
          api.logout();
        }
      }
      setLoading(false);
    };
    restoreSession();

    const handleExpiry = () => {
      setUser(null);
      setLoading(false);
    };
    window.addEventListener('auth:expired', handleExpiry);
    return () => window.removeEventListener('auth:expired', handleExpiry);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
    localStorage.setItem('stackdrive_session', JSON.stringify({ user: userData }));
  };

  const handleLogout = () => {
    // Intercept logout to play cinematic over the full screen
    setIsLoggingOutState(true);
  };

  const handleFinishLogout = () => {
    api.logout();
    setUser(null);
    setIsLoggingOutState(false);
  };

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-deep)',
      }}>
        <div className="spinner" style={{ width: 32, height: 32, borderWidth: 3, borderTopColor: 'var(--accent)' }} />
      </div>
    );
  }

  if (isLoggingOutState) {
    return <LogoutPage onFinishLogout={handleFinishLogout} />;
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/s/:token" element={<ShareLanding />} />
        <Route path="/login" element={<LoginPage onLogin={handleLogin} />} />
        <Route path="/signup" element={<SignupPage onLogin={handleLogin} />} />
        <Route path="/forgot" element={<ForgotPasswordPage />} />
        <Route path="/auth/google/callback" element={<GoogleCallback onLogin={handleLogin} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <>
      <Routes>
        <Route path="/s/:token" element={<ShareLanding />} />
        <Route path="*" element={
          <AuthenticatedApp
            user={user}
            setUser={setUser}
            onLogout={handleLogout}
            onFinishLogout={handleFinishLogout}
          />
        } />
      </Routes>
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AppContent />
      </ToastProvider>
    </BrowserRouter>
  );
}
