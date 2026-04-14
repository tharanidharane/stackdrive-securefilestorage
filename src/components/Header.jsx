import { Bell, User } from 'lucide-react';
import './Header.css';

export default function Header({ title, subtitle, unreadCount = 0, email }) {
  return (
    <header className="header">
      <div className="header__left">
        <h1 className="header__title">{title}</h1>
        {subtitle && <span className="header__subtitle">{subtitle}</span>}
      </div>
      <div className="header__right">
        <button className="header__bell" id="notification-bell">
          <Bell size={20} />
          {unreadCount > 0 && <span className="header__bell-dot" />}
        </button>
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
