import { useState, useEffect, useCallback } from 'react';
import { useToast } from '../components/Toast';
import Modal from '../components/Modal';
import api from '../services/api';
import { 
  Copy, 
  Trash2, 
  Clock, 
  Lock, 
  Unlock, 
  History, 
  ExternalLink,
  ShieldAlert,
  Download,
  AlertCircle
} from 'lucide-react';
import CustomSelect from '../components/CustomSelect';
import './SharedFiles.css';

export default function SharedFiles() {
  const extendOptions = [
    { value: 1, label: '+1 Hour' },
    { value: 12, label: '+12 Hours' },
    { value: 24, label: '+24 Hours' },
    { value: 48, label: '+48 Hours' },
    { value: 168, label: '+7 Days' }
  ];

  const [shares, setShares] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedShare, setSelectedShare] = useState(null);
  const [showDetail, setShowDetail] = useState(false);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [extendHours, setExtendHours] = useState(24);
  const { addToast } = useToast();

  const fetchShares = useCallback(async () => {
    try {
      const data = await api.getShares();
      setShares(data.shares || []);
    } catch (err) {
      if (err.status !== 401) {
        addToast('Failed to load shared links', 'error');
      }
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchShares();
    const interval = setInterval(fetchShares, 15000);
    return () => clearInterval(interval);
  }, [fetchShares]);

  const handleShareClick = async (share) => {
    setSelectedShare(share);
    setShowDetail(true);
    setLoadingAudit(true);
    try {
      const data = await api.getShareAudit(share.id);
      setAuditLogs(data.audit || []);
    } catch (err) {
      addToast('Failed to load access logs', 'error');
    } finally {
      setLoadingAudit(false);
    }
  };

  const handleCopy = (share) => {
    const shareUrl = `${window.location.origin}/s/${share.token}`;
    navigator.clipboard.writeText(shareUrl);
    addToast('Share link copied to clipboard!', 'success');
  };

  const handleRevoke = async (shareId) => {
    if (!window.confirm('Are you sure you want to revoke this share link? Recipients will immediately lose access.')) {
      return;
    }
    try {
      await api.revokeShare(shareId);
      addToast('Share link revoked successfully', 'success');
      setShowDetail(false);
      fetchShares();
    } catch (err) {
      addToast(err.message || 'Failed to revoke share link', 'error');
    }
  };

  const handleExtend = async (shareId) => {
    try {
      await api.extendShare(shareId, extendHours);
      addToast(`Expiration extended by ${extendHours} hours`, 'success');
      
      // Update local states
      const updatedShares = shares.map(s => {
        if (s.id === shareId) {
          const newExpiry = new Date(new Date(s.expiresAt).getTime() + extendHours * 60 * 60 * 1000);
          return { ...s, expiresAt: newExpiry.toISOString(), status: 'active' };
        }
        return s;
      });
      setShares(updatedShares);
      if (selectedShare?.id === shareId) {
        setSelectedShare(prev => ({
          ...prev,
          expiresAt: new Date(new Date(prev.expiresAt).getTime() + extendHours * 60 * 60 * 1000).toISOString(),
          status: 'active'
        }));
      }
    } catch (err) {
      addToast(err.message || 'Failed to extend share link', 'error');
    }
  };

  const getStatusClass = (share) => {
    const isExpired = new Date(share.expiresAt) < new Date();
    if (share.status === 'revoked') return 'share-status--revoked';
    if (isExpired || share.status === 'expired') return 'share-status--expired';
    return 'share-status--active';
  };

  const getStatusText = (share) => {
    const isExpired = new Date(share.expiresAt) < new Date();
    if (share.status === 'revoked') return 'Revoked';
    if (isExpired || share.status === 'expired') return 'Expired';
    return 'Active';
  };

  return (
    <div className="content-area">
      <div className="stagger-1">
        <h2 className="section-title">Shared Files</h2>
        <p className="section-subtitle">Monitor external file access, revoke links, and review verification logs</p>
      </div>

      <div className="stagger-2" style={{ marginTop: '24px' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '48px' }}>
            <div className="spinner" style={{ width: 32, height: 32 }} />
          </div>
        ) : shares.length === 0 ? (
          <div className="empty-shares">
            <AlertCircle size={40} style={{ color: 'var(--text-secondary)', marginBottom: '12px' }} />
            <h3 style={{ color: 'var(--text-primary)', marginBottom: '4px' }}>No active share links</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Go to File History or Dashboard, open a file and click "Share File" to start.</p>
          </div>
        ) : (
          <div className="file-table-wrapper">
            <table className="file-table">
              <thead>
                <tr>
                  <th style={{ width: '30%' }}>File Name</th>
                  <th style={{ width: '25%' }}>Expiration</th>
                  <th style={{ width: '12%' }}>Downloads</th>
                  <th style={{ width: '13%' }}>Protection</th>
                  <th style={{ width: '10%' }}>Status</th>
                  <th style={{ width: '10%', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {shares.map((share) => {
                  const shareUrl = `${window.location.origin}/s/${share.token}`;
                  return (
                    <tr key={share.id} className="file-table__row share-row" onClick={() => handleShareClick(share)}>
                      <td className="file-table__name">
                        <span className="mono">{share.fileName}</span>
                      </td>
                      <td className="file-table__time">
                        <span className="share-time" title={new Date(share.expiresAt).toLocaleString()}>
                          {new Date(share.expiresAt) < new Date() ? (
                            <span style={{ color: 'var(--color-threat)' }}>Expired</span>
                          ) : (
                            new Date(share.expiresAt).toLocaleString()
                          )}
                        </span>
                      </td>
                      <td className="file-table__size">
                        <span className="mono">
                          {share.downloads} / {share.maxDownloads === -1 ? '♾️' : share.maxDownloads}
                        </span>
                      </td>
                      <td>
                        {share.passwordProtected ? (
                          <span className="protection-badge protection-badge--secure" title="Password Protected">
                            <Lock size={13} /> Secure
                          </span>
                        ) : (
                          <span className="protection-badge protection-badge--open" title="No Password">
                            <Unlock size={13} /> Open
                          </span>
                        )}
                      </td>
                      <td>
                        <span className={`share-status ${getStatusClass(share)}`}>
                          {getStatusText(share)}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          <button 
                            className="icon-btn" 
                            title="Copy link"
                            onClick={() => handleCopy(share)}
                          >
                            <Copy size={16} />
                          </button>
                          <a 
                            href={shareUrl} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            className="icon-btn" 
                            title="Visit landing page"
                          >
                            <ExternalLink size={16} />
                          </a>
                          {share.status === 'active' && new Date(share.expiresAt) > new Date() && (
                            <button 
                              className="icon-btn icon-btn--danger" 
                              title="Revoke Share"
                              onClick={() => handleRevoke(share.id)}
                            >
                              <Trash2 size={16} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Share Management Modal */}
      <Modal
        isOpen={showDetail}
        onClose={() => {
          setShowDetail(false);
          setSelectedShare(null);
        }}
        title="Manage Shared Link"
        actions={
          <>
            {selectedShare?.status === 'active' && new Date(selectedShare.expiresAt) > new Date() && (
              <button 
                className="btn btn-danger" 
                style={{ width: 'auto' }}
                onClick={() => handleRevoke(selectedShare.id)}
              >
                Revoke Link
              </button>
            )}
            <button className="btn btn-secondary" onClick={() => setShowDetail(false)}>
              Close
            </button>
          </>
        }
      >
        {selectedShare && (
          <div className="share-detail-modal">
            <div className="file-detail">
              <div className="file-detail__row">
                <span className="file-detail__label">File Name</span>
                <span className="file-detail__value mono">{selectedShare.fileName}</span>
              </div>
              <div className="file-detail__row">
                <span className="file-detail__label">Created</span>
                <span className="file-detail__value">{new Date(selectedShare.createdAt).toLocaleString()}</span>
              </div>
              <div className="file-detail__row">
                <span className="file-detail__label">Expiration</span>
                <span className="file-detail__value">{new Date(selectedShare.expiresAt).toLocaleString()}</span>
              </div>
              <div className="file-detail__row">
                <span className="file-detail__label">Downloads Used</span>
                <span className="file-detail__value mono">
                  {selectedShare.downloads} / {selectedShare.maxDownloads === -1 ? 'Unlimited' : selectedShare.maxDownloads}
                </span>
              </div>
              <div className="file-detail__row">
                <span className="file-detail__label">Protection</span>
                <span className="file-detail__value">
                  {selectedShare.passwordProtected ? 'Password Enabled' : 'None (Open Link)'}
                </span>
              </div>
              <div className="file-detail__row">
                <span className="file-detail__label">Link status</span>
                <span className={`share-status ${getStatusClass(selectedShare)}`}>
                  {getStatusText(selectedShare)}
                </span>
              </div>
            </div>

            {/* Link Copy Bar */}
            <div className="share-link-bar">
              <input 
                type="text" 
                readOnly 
                value={`${window.location.origin}/s/${selectedShare.token}`} 
              />
              <button className="btn btn-primary" onClick={() => handleCopy(selectedShare)}>
                Copy Link
              </button>
            </div>

            {/* Extend Expiration Controls */}
            {selectedShare.status === 'active' && new Date(selectedShare.expiresAt) > new Date() && (
              <div className="extend-section">
                <h4 className="detail-section-title">Extend Link Lifetime</h4>
                <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                  <CustomSelect
                    value={extendHours}
                    onChange={(e) => setExtendHours(Number(e.target.value))}
                    options={extendOptions}
                    style={{ flex: 1 }}
                  />
                  <button className="btn" style={{ width: 'auto' }} onClick={() => handleExtend(selectedShare.id)}>
                    Extend Expiry
                  </button>
                </div>
              </div>
            )}

            {/* Audit Log / Event Logs */}
            <div className="audit-section">
              <h4 className="detail-section-title">Access & Audit Trail</h4>
              {loadingAudit ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '16px' }}>
                  <div className="spinner" style={{ width: 20, height: 20 }} />
                </div>
              ) : auditLogs.length === 0 ? (
                <p className="no-audit-text">No access attempts recorded yet.</p>
              ) : (
                <div className="audit-list">
                  {auditLogs.map((log) => {
                    let icon = <History size={14} />;
                    let colorClass = 'audit-icon--info';
                    
                    if (log.event === 'download') {
                      icon = <Download size={14} />;
                      colorClass = 'audit-icon--success';
                    } else if (log.event.includes('wrong') || log.event.includes('fail') || log.event.includes('expired')) {
                      icon = <ShieldAlert size={14} />;
                      colorClass = 'audit-icon--danger';
                    }

                    return (
                      <div key={log.id} className="audit-item">
                        <div className={`audit-icon ${colorClass}`}>
                          {icon}
                        </div>
                        <div className="audit-info">
                          <div className="audit-top">
                            <span className="audit-event">{log.event.replace('_', ' ').toUpperCase()}</span>
                            <span className="audit-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="audit-details">{log.details}</p>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                            <span>IP: {log.ipAddress}</span>
                            <span>{new Date(log.timestamp).toLocaleDateString()}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
