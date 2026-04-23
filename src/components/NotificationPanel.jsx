import { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, MailOpen, Clock } from 'lucide-react';
import api from '../services/api';
import './NotificationPanel.css';

export default function NotificationPanel({ onMarkAllRead }) {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchNotifications = async () => {
    try {
      const data = await api.getNotifications();
      setNotifications(data.notifications || []);
    } catch (e) {
      console.error('Failed to fetch notifications', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotifications();
    // Refresh every 30s
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleMarkRead = async () => {
    try {
      await api.markNotificationsRead();
      setNotifications(notifications.map(n => ({ ...n, read: true })));
      onMarkAllRead?.();
    } catch (e) {
      console.error('Failed to mark read', e);
    }
  };

  function getRelativeTime(isoStr) {
    const date = new Date(isoStr);
    const diff = (Date.now() - date.getTime()) / 1000;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  return (
    <div className="notification-panel" onClick={(e) => e.stopPropagation()}>
      <div className="notification-panel__header">
        <h3 className="notification-panel__title">Notifications</h3>
        {notifications.some(n => !n.read) && (
          <button className="notification-panel__mark-read" onClick={handleMarkRead}>
            Mark all as read
          </button>
        )}
      </div>

      <div className="notification-panel__list">
        {loading ? (
          <div className="notification-panel__empty">
            <div className="spinner" style={{ width: 24, height: 24 }} />
            <p>Loading notifications...</p>
          </div>
        ) : notifications.length === 0 ? (
          <div className="notification-panel__empty">
            <MailOpen size={32} />
            <p>All clear! No recent threats detected.</p>
          </div>
        ) : (
          notifications.map((n) => (
            <div key={n.id} className={`notification-item ${!n.read ? 'notification-item--unread' : ''}`}>
              <div className={`notification-item__icon ${n.threatType.includes('SAFE') ? 'notification-item__icon--pass' : 'notification-item__icon--threat'}`}>
                {n.threatType.includes('SAFE') ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
              </div>
              <div className="notification-item__content">
                <div className="notification-item__header">
                  <span className="notification-item__filename">{n.fileName}</span>
                  <span className="notification-item__time">{getRelativeTime(n.detectedAt)}</span>
                </div>
                <p className="notification-item__detail">
                  <span className={n.threatType.includes('SAFE') ? 'text-safe' : 'text-threat'}>
                    {n.threatType}
                  </span>
                  {' — detected by '}
                  {n.layer}
                </p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
