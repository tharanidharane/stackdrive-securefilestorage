import { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, ShieldX, ScanLine, Clock, Eye, EyeOff } from 'lucide-react';
import StatCard from '../components/StatCard';
import FileTable from '../components/FileTable';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';
import { useToast } from '../components/Toast';
import CustomSelect from '../components/CustomSelect';
import api from '../services/api';
import './Dashboard.css';

export default function Dashboard({ user }) {
  const expiryOptions = [
    { value: '10m', label: '10 Minutes' },
    { value: '1h', label: '1 Hour' },
    { value: '24h', label: '24 Hours' },
    { value: '7d', label: '7 Days' },
    { value: 'custom', label: 'Custom...' }
  ];

  const expiryUnitOptions = [
    { value: 'm', label: 'Minutes' },
    { value: 'h', label: 'Hours' },
    { value: 'd', label: 'Days' }
  ];

  const limitOptions = [
    { value: 1, label: 'One-time download' },
    { value: 5, label: '5 downloads' },
    { value: -1, label: 'Unlimited until expiry' },
    { value: 'custom', label: 'Custom...' }
  ];

  const [files, setFiles] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showDetail, setShowDetail] = useState(false);
  const [isSharing, setIsSharing] = useState(false);
  const [shareHours, setShareHours] = useState(24);
  const [generatedLink, setGeneratedLink] = useState(null);
  
  // Advanced sharing states
  const [shareConfigOpen, setShareConfigOpen] = useState(false);
  const [shareExpiry, setShareExpiry] = useState('24h');
  const [shareLimit, setShareLimit] = useState(-1);
  const [passwordEnabled, setPasswordEnabled] = useState(false);
  const [sharePassword, setSharePassword] = useState('');
  const [customExpiryValue, setCustomExpiryValue] = useState('24');
  const [customExpiryUnit, setCustomExpiryUnit] = useState('h');
  const [customLimitValue, setCustomLimitValue] = useState('10');
  const [showPassword, setShowPassword] = useState(false);
  
  const { addToast } = useToast();

  const awsConnected = user?.aws_connected !== false;

  // Fetch dashboard data
  const fetchData = useCallback(async () => {
    try {
      const [metricsData, filesData] = await Promise.all([
        api.getDashboardMetrics(),
        api.getFiles(),
      ]);
      setMetrics(metricsData);
      setFiles(filesData.files || []);
    } catch (err) {
      if (err.status !== 401) addToast('Failed to load dashboard data', 'error');
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchData();
    // Refresh metrics every 10s
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleRowClick = async (file) => {
    try {
      const data = await api.getFile(file.id);
      setSelectedFile(data.file);
    } catch {
      setSelectedFile(file);
    }
    setGeneratedLink(null);
    setShowDetail(true);
  };

  const handleDownload = async (file) => {
    try {
      const blob = await api.downloadFile(file.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      a.click();
      URL.revokeObjectURL(url);
      addToast('Download started', 'success');
      setShowDetail(false);
    } catch (err) {
      addToast(err.message || 'Download failed', 'error');
    }
  };

  const handleShare = async (file) => {
    setIsSharing(true);
    try {
      const finalExpiry = shareExpiry === 'custom' 
        ? `${customExpiryValue}${customExpiryUnit}` 
        : shareExpiry;
      const finalLimit = shareLimit === 'custom'
        ? Number(customLimitValue)
        : Number(shareLimit);

      const data = await api.createShareLink(file.id, {
        expires_in: finalExpiry,
        max_downloads: finalLimit,
        password: passwordEnabled && sharePassword ? sharePassword : null
      });
      const shareUrl = `${window.location.origin}/s/${data.token}`;
      setGeneratedLink(shareUrl);
      addToast('Secure share link created!', 'success');
    } catch (err) {
      addToast(err.message || 'Failed to create share link', 'error');
    } finally {
      setIsSharing(false);
    }
  };

  return (
    <>
      <div className="content-area">
        {/* Metric Cards */}
        <div className="metrics-grid stagger-1">
          <StatCard
            label={metrics?.filesSafe?.label || 'Files Safe'}
            value={metrics?.filesSafe?.value ?? 0}
            sublabel={metrics?.filesSafe?.sublabel || ''}
            icon={ShieldCheck}
            status="safe"
          />
          <StatCard
            label={metrics?.threatsBlocked?.label || 'Threats Blocked'}
            value={metrics?.threatsBlocked?.value ?? 0}
            sublabel={metrics?.threatsBlocked?.sublabel || ''}
            icon={ShieldX}
            status="threat"
          />
          <StatCard
            label={metrics?.scanningNow?.label || 'Scanning Now'}
            value={metrics?.scanningNow?.value ?? 0}
            sublabel={metrics?.scanningNow?.sublabel || ''}
            icon={ScanLine}
            status="scan"
          />
          <StatCard
            label={metrics?.inQuarantine?.label || 'In Quarantine'}
            value={metrics?.inQuarantine?.value ?? 0}
            sublabel={metrics?.inQuarantine?.sublabel || ''}
            icon={Clock}
            status="queue"
          />
        </div>

        {/* Recent File History */}
        <div className="stagger-2">
          <h2 className="section-title" style={{ marginTop: 'var(--space-8)' }}>Recent Files</h2>
          <FileTable
            files={files.slice(0, 7)}
            loading={loading}
            onRowClick={handleRowClick}
          />
        </div>
      </div>
      <Modal
        isOpen={showDetail}
        onClose={() => {
          setShowDetail(false);
          setGeneratedLink(null);
          setShareConfigOpen(false);
          setPasswordEnabled(false);
          setSharePassword('');
        }}
        title="File Details"
        actions={
          selectedFile?.status === 'safe' ? (
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              {!shareConfigOpen ? (
                <>
                  <button 
                    className="btn" 
                    style={{ width: 'auto', background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', border: '1px solid rgba(59, 130, 246, 0.2)' }}
                    onClick={() => setShareConfigOpen(true)}
                  >
                    Share File
                  </button>
                  <button className="btn btn-primary" style={{ width: 'auto' }}
                    onClick={() => handleDownload(selectedFile)}>
                    Download File
                  </button>
                </>
              ) : generatedLink ? (
                <button className="btn" style={{ width: 'auto' }} onClick={() => {
                  setShareConfigOpen(false);
                  setGeneratedLink(null);
                }}>
                  Done
                </button>
              ) : (
                <>
                  <button className="btn" style={{ width: 'auto' }} onClick={() => setShareConfigOpen(false)}>
                    Back
                  </button>
                  <button 
                    className="btn btn-primary" 
                    style={{ width: 'auto' }}
                    onClick={() => handleShare(selectedFile)}
                    disabled={isSharing}
                  >
                    {isSharing ? 'Generating...' : 'Generate Secure Link'}
                  </button>
                </>
              )}
            </div>
          ) : null
        }
      >
        {selectedFile && (
          <div className="file-detail">
            {shareConfigOpen ? (
              <div>
                <h3 style={{ color: 'var(--text-primary)', marginBottom: '20px', fontSize: '1.1rem', fontWeight: '600' }}>Configure Secure Share</h3>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Expiration Time</label>
                    <CustomSelect
                      value={shareExpiry}
                      onChange={(e) => setShareExpiry(e.target.value)}
                      options={expiryOptions}
                      disabled={!!generatedLink}
                    />
                    {shareExpiry === 'custom' && (
                      <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
                          <button
                            type="button"
                            onClick={() => setCustomExpiryValue(prev => Math.max(1, parseInt(prev || 0) - 1).toString())}
                            style={{
                              background: 'rgba(30, 41, 59, 0.8)',
                              color: 'var(--text-primary)',
                              border: '1px solid var(--bg-border)',
                              borderRight: 'none',
                              borderRadius: 'var(--radius-md) 0 0 var(--radius-md)',
                              width: '40px',
                              height: '42px',
                              cursor: 'pointer',
                              fontSize: '1.2rem',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              transition: 'all var(--transition-base)',
                              outline: 'none'
                            }}
                            disabled={!!generatedLink}
                          >
                            -
                          </button>
                          <input
                            type="number"
                            min="1"
                            value={customExpiryValue}
                            onChange={(e) => setCustomExpiryValue(e.target.value)}
                            style={{
                              flex: 1,
                              background: 'rgba(15, 23, 42, 0.8)',
                              color: 'var(--text-primary)',
                              border: '1px solid var(--bg-border)',
                              borderRadius: 0,
                              height: '42px',
                              textAlign: 'center',
                              outline: 'none',
                              WebkitAppearance: 'none',
                              MozAppearance: 'textfield'
                            }}
                            placeholder="Value"
                            disabled={!!generatedLink}
                          />
                          <button
                            type="button"
                            onClick={() => setCustomExpiryValue(prev => (parseInt(prev || 0) + 1).toString())}
                            style={{
                              background: 'rgba(30, 41, 59, 0.8)',
                              color: 'var(--text-primary)',
                              border: '1px solid var(--bg-border)',
                              borderLeft: 'none',
                              borderRadius: '0 var(--radius-md) var(--radius-md) 0',
                              width: '40px',
                              height: '42px',
                              cursor: 'pointer',
                              fontSize: '1.2rem',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              transition: 'all var(--transition-base)',
                              outline: 'none'
                            }}
                            disabled={!!generatedLink}
                          >
                            +
                          </button>
                        </div>
                        <CustomSelect
                          value={customExpiryUnit}
                          onChange={(e) => setCustomExpiryUnit(e.target.value)}
                          options={expiryUnitOptions}
                          disabled={!!generatedLink}
                          style={{ width: '130px' }}
                        />
                      </div>
                    )}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Download Limit</label>
                    <CustomSelect
                      value={shareLimit === 1 || shareLimit === 5 || shareLimit === -1 ? shareLimit : 'custom'}
                      onChange={(e) => {
                        const val = e.target.value;
                        if (val === 'custom') {
                          setShareLimit('custom');
                        } else {
                          setShareLimit(Number(val));
                        }
                      }}
                      options={limitOptions}
                      disabled={!!generatedLink}
                    />
                    {shareLimit === 'custom' && (
                      <div style={{ display: 'flex', alignItems: 'center', marginTop: '6px' }}>
                        <button
                          type="button"
                          onClick={() => setCustomLimitValue(prev => Math.max(1, parseInt(prev || 0) - 1).toString())}
                          style={{
                            background: 'rgba(30, 41, 59, 0.8)',
                            color: 'var(--text-primary)',
                            border: '1px solid var(--bg-border)',
                            borderRight: 'none',
                            borderRadius: 'var(--radius-md) 0 0 var(--radius-md)',
                            width: '40px',
                            height: '42px',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            transition: 'all var(--transition-base)',
                            outline: 'none'
                          }}
                          disabled={!!generatedLink}
                        >
                          -
                        </button>
                        <input
                          type="number"
                          min="1"
                          value={customLimitValue}
                          onChange={(e) => setCustomLimitValue(e.target.value)}
                          style={{
                            flex: 1,
                            background: 'rgba(15, 23, 42, 0.8)',
                            color: 'var(--text-primary)',
                            border: '1px solid var(--bg-border)',
                            borderRadius: 0,
                            height: '42px',
                            textAlign: 'center',
                            outline: 'none',
                            WebkitAppearance: 'none',
                            MozAppearance: 'textfield'
                          }}
                          placeholder="Downloads limit"
                          disabled={!!generatedLink}
                        />
                        <button
                          type="button"
                          onClick={() => setCustomLimitValue(prev => (parseInt(prev || 0) + 1).toString())}
                          style={{
                            background: 'rgba(30, 41, 59, 0.8)',
                            color: 'var(--text-primary)',
                            border: '1px solid var(--bg-border)',
                            borderLeft: 'none',
                            borderRadius: '0 var(--radius-md) var(--radius-md) 0',
                            width: '40px',
                            height: '42px',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            transition: 'all var(--transition-base)',
                            outline: 'none'
                          }}
                          disabled={!!generatedLink}
                        >
                          +
                        </button>
                      </div>
                    )}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)', cursor: 'pointer', fontSize: '0.9rem' }}>
                      <input
                        type="checkbox"
                        checked={passwordEnabled}
                        onChange={(e) => setPasswordEnabled(e.target.checked)}
                        style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                        disabled={!!generatedLink}
                      />
                      <span>Enable Password Protection</span>
                    </label>
                    {passwordEnabled && (
                      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                        <input
                          type={showPassword ? 'text' : 'password'}
                          placeholder="Enter password"
                          value={sharePassword}
                          onChange={(e) => setSharePassword(e.target.value)}
                          style={{
                            width: '100%',
                            background: 'rgba(15, 23, 42, 0.8)',
                            color: 'var(--text-primary)',
                            border: '1px solid var(--bg-border)',
                            borderRadius: 'var(--radius-md)',
                            padding: '10px 42px 10px 14px',
                            outline: 'none',
                            fontSize: '0.95rem'
                          }}
                          disabled={!!generatedLink}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          style={{
                            position: 'absolute',
                            right: '12px',
                            background: 'none',
                            border: 'none',
                            color: 'var(--text-secondary)',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            padding: 0,
                            outline: 'none'
                          }}
                          disabled={!!generatedLink}
                        >
                          {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {generatedLink && (
                  <div style={{
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    borderRadius: '8px',
                    padding: '16px',
                    marginTop: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px'
                  }}>
                    <span style={{ color: '#10b981', fontWeight: 'bold', fontSize: '0.9rem' }}>✨ Secure Link Generated Successfully</span>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <input 
                        type="text" 
                        readOnly 
                        value={generatedLink}
                        style={{
                          flex: 1,
                          background: 'rgba(15, 23, 42, 0.6)',
                          color: 'var(--text-primary)',
                          border: '1px solid var(--bg-border)',
                          borderRadius: '4px',
                          padding: '8px 12px',
                          outline: 'none',
                          fontSize: '0.9rem'
                        }}
                      />
                      <button 
                        className="btn btn-primary"
                        style={{ padding: '8px 16px', width: 'auto' }}
                        onClick={() => {
                          navigator.clipboard.writeText(generatedLink);
                          addToast('Copied to clipboard!', 'success');
                        }}
                      >
                        Copy Link
                      </button>
                    </div>
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                      Share this link with anyone. The recipient will require your password to download if set.
                    </span>
                  </div>
                )}
              </div>
            ) : (
              <>
                <div className="file-detail__row">
                  <span className="file-detail__label">File Name</span>
                  <span className="file-detail__value mono">{selectedFile.name}</span>
                </div>
                <div className="file-detail__row">
                  <span className="file-detail__label">Size</span>
                  <span className="file-detail__value">{selectedFile.size} {selectedFile.sizeUnit}</span>
                </div>
                <div className="file-detail__row">
                  <span className="file-detail__label">Uploaded</span>
                  <span className="file-detail__value">{new Date(selectedFile.uploadedAt).toLocaleString()}</span>
                </div>
                <div className="file-detail__row">
                  <span className="file-detail__label">Status</span>
                  <StatusBadge status={selectedFile.status} />
                </div>
                {selectedFile.risk !== null && selectedFile.risk !== undefined && (
                  <div className="file-detail__row">
                    <span className="file-detail__label">Risk Score</span>
                    <span className={`file-detail__value mono ${
                      selectedFile.risk < 10 ? 'text-safe' :
                      selectedFile.risk <= 60 ? 'text-queue' : 'text-threat'
                    }`}>{selectedFile.risk}%</span>
                  </div>
                )}
                {selectedFile.sha256 && (
                  <div className="file-detail__row">
                    <span className="file-detail__label">SHA-256</span>
                    <span className="file-detail__value mono" style={{ fontSize: 'var(--text-xs)', wordBreak: 'break-all' }}>
                      {selectedFile.sha256}
                    </span>
                  </div>
                )}
                {selectedFile.pipelineStages?.length > 0 && (
                  <>
                    <div className="file-detail__separator" />
                    <h4 className="file-detail__section-title">Pipeline Results</h4>
                    {selectedFile.pipelineStages.map((stage, i) => (
                      <div className="file-detail__stage" key={i}>
                        <span className={`file-detail__stage-dot ${
                          stage.status === 'pass' ? 'text-pass' :
                          stage.status === 'fail' ? 'text-threat' : 'text-muted'
                        }`}>
                          {stage.status === 'pass' ? '●' : stage.status === 'fail' ? '●' : '○'}
                        </span>
                        <span className="file-detail__stage-name">{stage.name}</span>
                        <span className={`file-detail__stage-status ${
                          stage.status === 'pass' ? 'text-pass' :
                          stage.status === 'fail' ? 'text-threat' : 'text-muted'
                        }`}>{stage.status.toUpperCase()}</span>
                      </div>
                    ))}
                    {selectedFile.status === 'safe' && (
                      <>
                        <div className="file-detail__separator" />
                        <h4 className="file-detail__section-title">Encryption Metadata</h4>
                        <div className="file-detail__row">
                          <span className="file-detail__label">Algorithm</span>
                          <span className="file-detail__value mono">AES-256-GCM</span>
                        </div>
                        <div className="file-detail__row">
                          <span className="file-detail__label">Key Management</span>
                          <span className="file-detail__value mono">AWS KMS (CMK)</span>
                        </div>
                        <div className="file-detail__row">
                          <span className="file-detail__label">PQ Wrapping</span>
                          <span className="file-detail__value mono">Kyber-1024</span>
                        </div>
                        <div className="file-detail__row">
                          <span className="file-detail__label">Signature</span>
                          <span className="file-detail__value mono">Dilithium-3</span>
                        </div>
                      </>
                    )}
                  </>
                )}
              </>
            )}
          </div>
        )}
      </Modal>
    </>
  );
}
