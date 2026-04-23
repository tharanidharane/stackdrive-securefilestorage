import { useState, useEffect, useRef } from 'react';
import { Bell, User } from 'lucide-react';
import NotificationPanel from './NotificationPanel';
import './Header.css';

export default function Header({ title, subtitle, unreadCount = 0, email, onMarkAllRead }) {
  const [isOpen, setIsOpen] = useState(false);
  const bellRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (bellRef.current && !bellRef.current.contains(event.target)) {
        setIsOpen(false);
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
            className={`header__bell ${isOpen ? 'active' : ''}`} 
            id="notification-bell"
            onClick={() => setIsOpen(!isOpen)}
          >
            <Bell size={20} />
            {unreadCount > 0 && <span className="header__bell-dot" />}
          </button>
          
          {isOpen && (
            <NotificationPanel onMarkAllRead={() => {
              onMarkAllRead?.();
              // Keep panel open but count is 0
            }} />
          )}
        </div>

        <div className="header__user">
          <div className="header__avatar" id="user-avatar">
            <User size={16} />
          </div>
          <span className="header__email">{email || 'user@stackdrive.io'}</span>
        </div>
      </div>
    </header>
  );
}
