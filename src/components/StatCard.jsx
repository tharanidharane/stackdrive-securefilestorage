import { useCountUp } from '../hooks/useCountUp';
import './StatCard.css';

const statusColorMap = {
  safe: 'var(--color-safe)',
  threat: 'var(--color-threat)',
  scan: 'var(--color-scan)',
  queue: 'var(--color-queue)',
};

export default function StatCard({ label, value, sublabel, icon: Icon, status, className = '' }) {
  const displayValue = useCountUp(value, 800);
  const color = statusColorMap[status] || 'var(--text-primary)';

  return (
    <div className={`stat-card ${className}`} style={{ '--card-color': color }}>
      <div className="stat-card__top-accent" />
      <div className="stat-card__header">
        <span className="stat-card__label">{label}</span>
        {Icon && (
          <div className="stat-card__icon-wrapper">
            <Icon size={24} />
          </div>
        )}
      </div>
      <div className="stat-card__value" style={{ color }}>
        {displayValue.toLocaleString()}
      </div>
      {sublabel && (
        <span className={`stat-card__sublabel ${status === 'safe' ? 'stat-card__sublabel--pulse' : ''}`}>
          {sublabel}
        </span>
      )}
    </div>
  );
}
