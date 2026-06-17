import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import api from '../services/api';
import Modal from '../components/Modal';
import { Lock, Download, AlertTriangle, ShieldCheck, Mail, Key, Eye, EyeOff } from 'lucide-react';

export default function ShareLanding() {
  const { token } = useParams();
  const [shareInfo, setShareInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [timeLeft, setTimeLeft] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [downloadWarning, setDownloadWarning] = useState(null);
  const [showIntegrityModal, setShowIntegrityModal] = useState(false);
  const [integrityReasons, setIntegrityReasons] = useState([]);

  // Fetch share metadata on mount
  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const data = await api.getShareInfo(token);
        setShareInfo(data.share);
      } catch (err) {
        setError(err.message || 'The shared link is invalid, expired, or has exceeded its download limit.');
      } finally {
        setLoading(false);
      }
    };
    fetchInfo();
  }, [token]);

  // Expiration countdown
  useEffect(() => {
    if (!shareInfo?.expiresAt) return;
    const updateTime = () => {
      const diff = new Date(shareInfo.expiresAt) - new Date();
      if (diff <= 0) {
        setTimeLeft('Expired');
        setError('This share link has expired.');
        return;
      }
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
      const minutes = Math.floor((diff / (1000 * 60)) % 60);
      const seconds = Math.floor((diff / 1000) % 60);
      
      let str = '';
      if (days > 0) str += `${days}d `;
      if (hours > 0 || days > 0) str += `${hours}h `;
      str += `${minutes}m ${seconds}s`;
      setTimeLeft(str);
    };
    
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, [shareInfo]);

  const triggerDownload = async () => {
    setDownloading(true);
    setDownloadWarning(null);
    try {
      const result = await api.downloadSharedFile(token, { password, email });
      
      if (result.integrityFailed) {
        setIntegrityReasons(result.reasons || []);
        setShowIntegrityModal(true);
        setDownloading(false);
        return;
      }

      const { blob, warning } = result;
      let downloadName = shareInfo.fileName;
      if (warning) {
        setDownloadWarning(warning);
        alert(`SECURITY WARNING: The downloaded file appears to have been modified or tampered with:\n\n${warning.split('; ').map(w => '• ' + w).join('\n')}`);
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setShowIntegrityModal(false);

      // Decrement local download count
      setShareInfo(prev => {
        if (!prev) return null;
        return {
          ...prev,
          downloads: prev.downloads + 1
        };
      });
    } catch (err) {
      alert(err.message || 'Download failed. Please check password and try again.');
    } finally {
      setDownloading(false);
    }
  };

  const handleDownload = async (e) => {
    e.preventDefault();
    if (!email) {
      alert('Recipient email is required to access the shared file.');
      return;
    }
    if (shareInfo.passwordProtected && !password) {
      alert('This share link is password-protected. Please enter the password.');
      return;
    }
    await triggerDownload();
  };

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-deep, #0f172a)',
        fontFamily: 'Inter, sans-serif'
      }}>
        <div className="spinner" style={{ width: 36, height: 36 }} />
      </div>
    );
  }

  if (error || !shareInfo) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
        fontFamily: 'Inter, sans-serif',
        padding: '20px'
      }}>
        <div style={{
          background: 'rgba(30, 41, 59, 0.7)',
          backdropFilter: 'blur(20px)',
          border: '1px solid rgba(239, 68, 68, 0.2)',
          borderRadius: '24px',
          padding: '40px 30px',
          textAlign: 'center',
          maxWidth: '440px',
          width: '100%',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.4)'
        }}>
          <div style={{ 
            background: 'rgba(239, 68, 68, 0.15)',
            width: '72px',
            height: '72px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '50%',
            margin: '0 auto 24px auto',
            color: '#ef4444'
          }}>
            <AlertTriangle size={36} />
          </div>
          
          <h1 style={{ color: 'white', margin: '0 0 16px 0', fontSize: '1.5rem', fontWeight: '700' }}>
            Link Expired or Invalid
          </h1>
          
          <p style={{ color: '#cbd5e1', fontSize: '0.95rem', lineHeight: '1.6', margin: '0 0 24px 0' }}>
            {error || 'This secure share link is no longer active. It may have expired, reached its download limit, or been revoked by the owner.'}
          </p>

          <div style={{ fontSize: '0.85rem', color: '#64748b', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '16px' }}>
            StackDrive Secure Gateway
          </div>
        </div>
      </div>
    );
  }

  const isExpired = new Date(shareInfo.expiresAt) < new Date();
  const maxReached = shareInfo.maxDownloads !== -1 && shareInfo.downloads >= shareInfo.maxDownloads;

  if (isExpired || maxReached) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
        fontFamily: 'Inter, sans-serif',
        padding: '20px'
      }}>
        <div style={{
          background: 'rgba(30, 41, 59, 0.7)',
          backdropFilter: 'blur(20px)',
          border: '1px solid rgba(239, 68, 68, 0.2)',
          borderRadius: '24px',
          padding: '40px 30px',
          textAlign: 'center',
          maxWidth: '440px',
          width: '100%',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.4)'
        }}>
          <div style={{ 
            background: 'rgba(239, 68, 68, 0.15)',
            width: '72px',
            height: '72px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '50%',
            margin: '0 auto 24px auto',
            color: '#ef4444'
          }}>
            <AlertTriangle size={36} />
          </div>
          
          <h1 style={{ color: 'white', margin: '0 0 16px 0', fontSize: '1.5rem', fontWeight: '700' }}>
            {maxReached ? 'Download Limit Reached' : 'Share Link Expired'}
          </h1>
          
          <p style={{ color: '#cbd5e1', fontSize: '0.95rem', lineHeight: '1.6', margin: '0 0 24px 0' }}>
            {maxReached 
              ? 'This file has reached the maximum number of allowed downloads.'
              : 'This secure sharing link has expired and is no longer available.'
            }
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #0f172a 0%, #111827 100%)',
      fontFamily: 'Inter, sans-serif',
      padding: '20px'
    }}>
      <div style={{
        background: 'rgba(30, 41, 59, 0.7)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '24px',
        padding: '40px 32px',
        maxWidth: '460px',
        width: '100%',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
      }}>
        {/* Header Icon */}
        <div style={{ 
          background: 'rgba(59, 130, 246, 0.12)',
          width: '64px',
          height: '64px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '50%',
          margin: '0 auto 20px auto',
          color: '#3b82f6'
        }}>
          <Lock size={30} />
        </div>
        
        <h1 style={{ color: 'white', margin: '0 0 8px 0', fontSize: '1.45rem', fontWeight: '700', textAlign: 'center' }}>
          Secure File Share
        </h1>
        
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', textAlign: 'center', margin: '0 0 24px 0' }}>
          This file is dynamically encrypted and monitored. Recipient verification is required.
        </p>

        {/* File Metadata Card */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.4)',
          border: '1px solid rgba(255, 255, 255, 0.05)',
          borderRadius: '12px',
          padding: '16px',
          marginBottom: '24px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>File Name</span>
            <span style={{ color: 'white', fontSize: '0.85rem', fontWeight: '600', fontFamily: 'monospace', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {shareInfo.fileName}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Expires In</span>
            <span style={{ color: '#f59e0b', fontSize: '0.85rem', fontWeight: '600' }}>
              {timeLeft}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Remaining Downloads</span>
            <span style={{ color: 'white', fontSize: '0.85rem', fontWeight: '600' }}>
              {shareInfo.maxDownloads === -1 
                ? 'Unlimited' 
                : `${shareInfo.maxDownloads - shareInfo.downloads} left`
              }
            </span>
          </div>
        </div>

        {/* Download Form */}
        <form onSubmit={handleDownload} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ color: '#cbd5e1', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Mail size={14} /> Recipient Email
            </label>
            <input
              type="email"
              placeholder="enter.your@email.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={downloading}
              style={{
                background: 'rgba(15, 23, 42, 0.6)',
                color: 'white',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                padding: '10px 14px',
                outline: 'none',
                fontSize: '0.9rem'
              }}
            />
            <span style={{ color: '#64748b', fontSize: '0.75rem' }}>
              Used to insert secure visible and invisible watermarks into the file.
            </span>
          </div>

          {shareInfo.passwordProtected && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ color: '#cbd5e1', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Key size={14} /> Password
              </label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter share password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  disabled={downloading}
                  style={{
                    width: '100%',
                    background: 'rgba(15, 23, 42, 0.6)',
                    color: 'white',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    padding: '10px 42px 10px 14px',
                    outline: 'none',
                    fontSize: '0.9rem'
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    background: 'none',
                    border: 'none',
                    color: '#94a3b8',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: 0,
                    outline: 'none'
                  }}
                  disabled={downloading}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>
          )}

          <button 
            type="submit"
            disabled={downloading}
            style={{
              background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
              color: 'white',
              border: 'none',
              padding: '14px 20px',
              borderRadius: '10px',
              fontSize: '1rem',
              fontWeight: '600',
              cursor: 'pointer',
              marginTop: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              boxShadow: '0 8px 20px rgba(59, 130, 246, 0.3)',
              transition: 'all 0.2s'
            }}
          >
            {downloading ? (
              <>
                <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
                <span>Decrypting & Streaming...</span>
              </>
            ) : (
              <>
                <Download size={18} />
                <span>Download Shared File</span>
              </>
            )}
          </button>
        </form>

        {downloadWarning && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '8px',
            padding: '12px 16px',
            marginTop: '20px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
            textAlign: 'left'
          }}>
            <AlertTriangle size={18} style={{ color: '#ef4444', flexShrink: 0, marginTop: '2px' }} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <span style={{ color: '#ef4444', fontWeight: 'bold', fontSize: '0.85rem' }}>Security Warning</span>
              {downloadWarning.split('; ').map((warn, i) => (
                <span key={i} style={{ color: '#fca5a5', fontSize: '0.8rem', lineHeight: '1.4' }}>
                  • {warn}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Footer Info */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginTop: '28px' }}>
          <ShieldCheck size={16} style={{ color: '#10b981' }} />
          <span style={{ color: '#10b981', fontSize: '0.8rem', fontWeight: '500' }}>
            Zero-Trust Ephemeral Decryption Gateway
          </span>
        </div>
      </div>

      <Modal
        isOpen={showIntegrityModal}
        onClose={() => setShowIntegrityModal(false)}
        title="⚠ Security Verification Failed"
        actions={
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', width: '100%' }}>
            <button className="btn btn-secondary" onClick={() => setShowIntegrityModal(false)}>
              Close
            </button>
          </div>
        }
      >
        <div style={{ color: 'var(--text-primary)', padding: '10px 0' }}>
          <p style={{ fontWeight: '600', color: '#ef4444', marginBottom: '14px', fontSize: '1.05rem' }}>
            This file failed integrity verification, indicating it has been modified or tampered with.
          </p>
          <p style={{ fontSize: '0.9rem', marginBottom: '12px', color: '#cbd5e1' }}>
            To protect your system, this download has been blocked.
          </p>
          {integrityReasons.length > 0 && (
            <div style={{ marginTop: '16px', padding: '10px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '6px' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#ef4444', display: 'block', marginBottom: '4px' }}>Failure Reasons:</span>
              <ul style={{ margin: 0, paddingLeft: '14px', fontSize: '0.8rem', color: 'white' }}>
                {integrityReasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
