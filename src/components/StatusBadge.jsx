import './StatusBadge.css';

const badgeConfig = {
  safe:       { label: 'SAFE',       className: 'badge--safe' },
  blocked:    { label: 'BLOCKED',    className: 'badge--blocked' },
  scanning:   { label: 'SCANNING',   className: 'badge--scanning' },
  quarantine: { label: 'QUARANTINE', className: 'badge--quarantine' },
  pass:       { label: 'PASS',       className: 'badge--pass' },
  running:    { label: 'RUNNING',    className: 'badge--scanning' },
  pending:    { label: 'PENDING',    className: 'badge--pending' },
  fail:       { label: 'FAILED',     className: 'badge--blocked' },
  skipped:    { label: 'SKIPPED',    className: 'badge--pending' },
};

export default function StatusBadge({ status, small = false }) {
  const config = badgeConfig[status] || badgeConfig.pending;
  return (
    <span className={`badge ${config.className} ${small ? 'badge--small' : ''}`}>
      {config.label}
    </span>
  );
}
