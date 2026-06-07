import { useState, useEffect, useRef } from 'react';
import { Bell, User, LogOut, Settings, ChevronDown } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import NotificationPanel from './NotificationPanel';
import './Header.css';

export default function Header({ title, subtitle, unreadCount = 0, email, onMarkAllRead, onLogout }) {
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const navigate = useNavigate();
  const bellRef = useRef(null);
  const profileRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (bellRef.current && !bellRef.current.contains(event.target)) {
        setNotifOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="header">
      <div className="header__left">
        <h1 className="header__title">{title}</h1>
        {subtitle && <span className="header__subtitle">{subtitle}</span>}
      </div>
      <div className="header__right">
        <div className="header__bell-wrapper" ref={bellRef}>
          <button 
            className={`header__bell ${notifOpen ? 'active' : ''}`} 
            id="notification-bell"
            onClick={() => setNotifOpen(!notifOpen)}
          >
            <Bell size={20} />
            {unreadCount > 0 && <span className="header__bell-dot" />}
          </button>
          
          {notifOpen && (
            <NotificationPanel onMarkAllRead={() => {
              onMarkAllRead?.();
            }} />
          )}
        </div>

        <div className="header__user-wrapper" ref={profileRef}>
          <button 
            className={`header__user ${profileOpen ? 'active' : ''}`}
            onClick={() => setProfileOpen(!profileOpen)}
            id="user-profile-menu"
            aria-label="User profile menu"
          >
            <div className="header__avatar" id="user-avatar">
              <User size={16} />
            </div>
            <span className="header__email">{email || 'user@stackdrive.io'}</span>
            <ChevronDown size={14} className={`header__chevron ${profileOpen ? 'open' : ''}`} />
          </button>

          {profileOpen && (
            <div className="header__dropdown" id="user-dropdown-menu">
              <div className="header__dropdown-header">
                <span className="header__dropdown-email">{email || 'user@stackdrive.io'}</span>
              </div>
              <hr className="header__dropdown-divider" />
              <button 
                className="header__dropdown-item" 
                onClick={() => {
                  setProfileOpen(false);
                  navigate('/settings');
                }}
              >
                <Settings size={14} />
                <span>Settings</span>
              </button>
              <button 
                className="header__dropdown-item header__dropdown-item--danger" 
                onClick={() => {
                  setProfileOpen(false);
                  onLogout?.();
                }}
                id="header-logout-btn"
              >
                <LogOut size={14} />
                <span>Log Out</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
