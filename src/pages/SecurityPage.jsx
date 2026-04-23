import { useState, useEffect } from 'react';
import { ShieldCheck, Fingerprint, Archive, Bug, Box, TrendingUp, AlertTriangle, Clock } from 'lucide-react';
import { useCountUp } from '../hooks/useCountUp';
import api from '../services/api';
import './SecurityPage.css';

function SecurityStatCard({ label, value, icon: Icon, color, suffix = '' }) {
  const displayValue = useCountUp(typeof value === 'number' ? value : 0, 800);
  return (
    <div className="security-stat" style={{ '--stat-color': color }}>
      <div className="security-stat__icon">
        <Icon size={20} />
      </div>
      <div className="security-stat__value">
        {typeof value === 'number' ? displayValue.toLocaleString() : value}{suffix}
      </div>
      <div className="security-stat__label">{label}</div>
    </div>
  );
}

const layerIcons = {
  'SHA-256 + VirusTotal': Fingerprint,
  'ZIP Heuristic Analysis': Archive,
  'ClamAV (Docker)': Bug,
  'Sandbox (Docker)': Box,
};

function getRelativeTime(isoStr) {
  const date = new Date(isoStr);
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function SecurityPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const data = await api.getSecurityStats();
        setStats(data);
      } catch { /* ignore */ }
      finally { setLoading(false); }
    };
    fetch();
    const interval = setInterval(fetch, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="content-area">
        <div className="stagger-1">
          <h2 className="section-title">Security Overview</h2>
          <p className="section-subtitle">Loading security data...</p>
        </div>
      </div>
    );
  }

  const layerStats = stats?.layerStats || [];
  const threats = stats?.recentThreats || [];

  return (
    <div className="content-area">
      <div className="stagger-1">
        <h2 className="section-title">Security Overview</h2>
        <p className="section-subtitle">Monitor your security pipeline performance and threat activity</p>
      </div>

      {/* Overview Stats */}
      <div className="security-stats-grid stagger-2">
        <SecurityStatCard label="Total Files Scanned" value={stats?.totalScanned || 0} icon={ShieldCheck} color="var(--color-pass)" />
        <SecurityStatCard label="Pass Rate" value={stats?.passRate || 0} icon={TrendingUp} color="var(--color-safe)" suffix="%" />
        <SecurityStatCard label="Avg Scan Time" value={stats?.avgScanTime || '—'} icon={Clock} color="var(--color-scan)" />
        <SecurityStatCard label="Active Threats" value={stats?.activeThreats || 0} icon={AlertTriangle} color="var(--color-threat)" />
      </div>

      {/* Layer Performance */}
      {layerStats.length > 0 && (
        <div className="stagger-3">
          <h3 className="section-title" style={{ fontSize: 'var(--text-lg)' }}>Layer Performance</h3>
          <div className="layer-cards">
            {layerStats.map((layer, i) => {
              const Icon = layerIcons[layer.name] || ShieldCheck;
              const total = layer.passed + layer.failed;
              const passRate = total > 0 ? ((layer.passed / total) * 100).toFixed(1) : '0.0';
              return (
                <div key={layer.name} className="layer-card">
                  <div className="layer-card__header">
                    <div className="layer-card__icon">
                      <Icon size={18} />
                    </div>
                    <div>
                      <h4 className="layer-card__name">Layer {i + 1}</h4>
                      <p className="layer-card__title">{layer.name}</p>
                    </div>
                  </div>
                  <div className="layer-card__bar">
                    <div className="layer-card__bar-fill" style={{ width: `${passRate}%` }} />
                  </div>
                  <div className="layer-card__stats">
                    <span className="text-safe">{layer.passed.toLocaleString()} passed</span>
                    <span className="text-threat">{layer.failed} failed</span>
                    <span className="text-muted">{passRate}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recent Threats */}
      {threats.length > 0 && (
        <div className="stagger-4" style={{ marginTop: 'var(--space-8)' }}>
          <h3 className="section-title" style={{ fontSize: 'var(--text-lg)' }}>Recent Threat Activity</h3>
          <div className="threat-list">
            {threats.map(threat => (
              <div key={threat.id} className="threat-item">
                <div className="threat-item__icon">
                  <AlertTriangle size={16} />
                </div>
                <div className="threat-item__content">
                  <div className="threat-item__header">
                    <span className="threat-item__filename mono">{threat.fileName}</span>
                    <span className="threat-item__time">{getRelativeTime(threat.detectedAt)}</span>
                  </div>
                  <p className="threat-item__detail">
                    <span className="text-threat">{threat.threatType}</span> — detected at {threat.layer}
                  </p>
                  <p className="threat-item__action">{threat.action}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Pipeline Description - always shown */}
      <div className="stagger-5" style={{ marginTop: 'var(--space-8)' }}>
        <h3 className="section-title" style={{ fontSize: 'var(--text-lg)' }}>Security Pipeline Layers</h3>
        <div className="pipeline-desc-grid">
          <div className="pipeline-desc-card">
            <div className="pipeline-desc-card__icon" style={{ color: 'var(--color-pass)' }}>
              <Fingerprint size={24} />
            </div>
            <h4>Layer 1 — SHA-256 + VirusTotal</h4>
            <p>Computes SHA-256 hash and queries VirusTotal threat intelligence API. Checks against 70+ antivirus engines with result caching and rate limit handling.</p>
          </div>
          <div className="pipeline-desc-card">
            <div className="pipeline-desc-card__icon" style={{ color: 'var(--color-scan)' }}>
              <Archive size={24} />
            </div>
            <h4>Layer 2 — ZIP Heuristic Analysis</h4>
            <p>Deep archive heuristic scan. Detects ZIP bombs, path traversal attacks, hidden files, obfuscated filenames, nested archives, excessive file counts, and dangerous executables.</p>
          </div>
          <div className="pipeline-desc-card">
            <div className="pipeline-desc-card__icon" style={{ color: 'var(--color-queue)' }}>
              <Bug size={24} />
            </div>
            <h4>Layer 3 — ClamAV (Docker)</h4>
            <p>Signature-based antivirus scan via a persistent ClamAV (clamd) container. Real-time scanning over TCP socket with single-second latency.</p>
          </div>
          <div className="pipeline-desc-card">
            <div className="pipeline-desc-card__icon" style={{ color: 'var(--color-threat)' }}>
              <Box size={24} />
            </div>
            <h4>Layer 4 — Sandbox (Docker)</h4>
            <p>Behavioral analysis in a fully isolated ephemeral container. Monitors syscalls via strace, computes entropy, scans for suspicious strings, and applies heuristic risk scoring.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
