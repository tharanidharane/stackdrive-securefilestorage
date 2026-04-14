import { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ToastProvider, useToast } from './components/Toast';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import Dashboard from './pages/Dashboard';
import UploadPage from './pages/UploadPage';
import FileHistory from './pages/FileHistory';
import SecurityPage from './pages/SecurityPage';
import SettingsPage from './pages/SettingsPage';
import api from './services/api';

const pageTitles = {
  '/overview': { title: 'Dashboard', subtitle: 'Overview of your security posture' },
  '/upload': { title: 'Upload', subtitle: 'Secure file ingestion' },
  '/history': { title: 'File History', subtitle: 'All uploaded files' },
  '/security': { title: 'Security', subtitle: 'Pipeline performance & threats' },
  '/settings': { title: 'Settings', subtitle: 'Account & AWS configuration' },
};

function AuthenticatedApp({ user, setUser, onLogout }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

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
        <HeaderWithTitle unreadCount={unreadCount} email={user?.email} />
        <div className="main-content">
          <Routes>
            <Route path="/overview" element={<Dashboard user={user} />} />
            <Route path="/upload" element={<UploadPage user={user} />} />
            <Route path="/history" element={<FileHistory />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/settings" element={
              <SettingsPage
                user={user}
                onUpdateUser={handleUpdateUser}
                onLogout={onLogout}
              />
            } />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

function HeaderWithTitle({ unreadCount, email }) {
  const location = useLocation();
  const pageInfo = pageTitles[location.pathname] || { title: 'StackDrive', subtitle: '' };
  return <Header title={pageInfo.title} subtitle={pageInfo.subtitle}
                 unreadCount={unreadCount} email={email} />;
}

function AppContent() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Restore session on mount
  useEffect(() => {
    const restoreSession = async () => {
      const token = api.getToken();
      if (token) {
        try {
          const data = await api.getMe();
          setUser(data.user);
          // Store in localStorage too
          localStorage.setItem('stackdrive_session', JSON.stringify({ user: data.user }));
        } catch (e) {
          api.logout();
        }
      }
      setLoading(false);
    };
    restoreSession();

    // Listen for auth expiry
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
    api.logout();
    setUser(null);
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

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage onLogin={handleLogin} />} />
        <Route path="/signup" element={<SignupPage onLogin={handleLogin} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <AuthenticatedApp
      user={user}
      setUser={setUser}
      onLogout={handleLogout}
    />
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
