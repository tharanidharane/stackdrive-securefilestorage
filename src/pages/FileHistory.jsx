import { useState, useEffect, useCallback } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import FileTable from '../components/FileTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import { useToast } from '../components/Toast';
import api from '../services/api';
import CustomSelect from '../components/CustomSelect';
import './FileHistory.css';

const filterTabs = ['all', 'safe', 'blocked', 'scanning', 'quarantine'];

export default function FileHistory() {
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

  const [activeFilter, setActiveFilter] = useState('all');
  const [files, setFiles] = useState([]);
  const [allFiles, setAllFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showDetail, setShowDetail] = useState(false);
  const [integrityFailedFile, setIntegrityFailedFile] = useState(null);
  const [integrityReasons, setIntegrityReasons] = useState([]);
  const [showIntegrityModal, setShowIntegrityModal] = useState(false);

  // Advanced sharing states
  const [isSharing, setIsSharing] = useState(false);
  const [generatedLink, setGeneratedLink] = useState(null);
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

  const fetchFiles = useCallback(async () => {
    try {
      const data = await api.getFiles(activeFilter);
      setFiles(data.files || []);
      if (activeFilter === 'all') setAllFiles(data.files || []);
    } catch (err) {
      if (err.status !== 401) addToast('Failed to load files', 'error');
    } finally {
      setLoading(false);
    }
  }, [activeFilter, addToast]);

  // Fetch all files for tab counts
  useEffect(() => {
    const fetchAll = async () => {
      try {
        const data = await api.getFiles('all');
        setAllFiles(data.files || []);
      } catch { /* ignore */ }
    };
    fetchAll();
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchFiles();
  }, [fetchFiles]);

  // Auto-refresh every 10s
  useEffect(() => {
    const interval = setInterval(fetchFiles, 10000);
    return () => clearInterval(interval);
  }, [fetchFiles]);

  const getCount = (status) => {
    if (status === 'all') return allFiles.length;
    return allFiles.filter(f => f.status === status).length;
  };

  const handleRowClick = async (file) => {
    try {
      const data = await api.getFile(file.id);
      setSelectedFile(data.file);
    } catch {
      setSelectedFile(file);
    }
    setGeneratedLink(null);
    setShareConfigOpen(false);
    setPasswordEnabled(false);
    setSharePassword('');
    setShowDetail(true);
  };

  const handleDownload = async (file, forceRecovery = false) => {
    try {
      const result = await api.downloadFile(file.id, forceRecovery);
      
      if (result.integrityFailed) {
        setIntegrityFailedFile(file);
        setIntegrityReasons(result.reasons || []);
        setShowIntegrityModal(true);
        setShowDetail(false);
        return;
      }

      const { blob, warning } = result;
      let downloadName = file.name;
      if (forceRecovery) {
        const dotIdx = file.name.lastIndexOf('.');
        if (dotIdx !== -1) {
          downloadName = `${file.name.substring(0, dotIdx)}_corrupted${file.name.substring(dotIdx)}`;
        } else {
          downloadName = `${file.name}_corrupted`;
        }
        
        localStorage.setItem('recovery_banner_active', 'true');
        window.dispatchEvent(new Event('storage'));
        window.dispatchEvent(new Event('recovery_banner_update'));
        
        addToast(
          '⚠️ Recovery Copy Downloaded. This file failed integrity verification and may be corrupted or modified. Use with caution.',
          'warning',
          10000
        );
      } else if (warning) {
        const warningList = warning.split('; ');
        warningList.forEach(warn => {
          addToast(`SECURITY WARNING: ${warn}`, 'warning', 10000);
        });
      } else {
        addToast('Download started', 'success');
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = downloadName;
      a.click();
      URL.revokeObjectURL(url);
      setShowDetail(false);
      setShowIntegrityModal(false);
      fetchFiles();
    } catch (err) {
      addToast(err.message || 'Download failed', 'error');
    }
  };

  const handleDelete = async (file) => {
    try {
      await api.deleteFile(file.id);
      addToast(`${file.name} deleted`, 'success');
      setShowDetail(false);
      fetchFiles();
    } catch (err) {
      addToast(err.message || 'Delete failed', 'error');
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
    <div className="content-area">
      <div className="stagger-1">
        <h2 className="section-title">File History</h2>
        <p className="section-subtitle">View and manage all your uploaded files</p>
      </div>

      <div className="filter-tabs stagger-2">
        {filterTabs.map(tab => (
          <button
            key={tab}
            className={`filter-tab ${activeFilter === tab ? 'active' : ''}`}
            onClick={() => setActiveFilter(tab)}
            id={`filter-${tab}`}
          >
            {tab}
            <span className="filter-tab__count">{getCount(tab)}</span>
          </button>
        ))}
      </div>

      <div className="stagger-3">
        <FileTable
          files={files}
          loading={loading}
          onRowClick={handleRowClick}
        />
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
                    Download
                  </button>
                  <button className="btn btn-danger" style={{ width: 'auto' }}
                    onClick={() => handleDelete(selectedFile)}>
                    Delete
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
          ) : (
            <>
              <button className="btn btn-danger" style={{ width: 'auto' }}
                onClick={() => handleDelete(selectedFile)}>
                Delete
              </button>
              <button className="btn btn-secondary" onClick={() => setShowDetail(false)}>
                Close
              </button>
            </>
          )
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
                <div className="file-detail__row">
                  <span className="file-detail__label">Checks</span>
                  <span className="file-detail__value">{selectedFile.checks}</span>
                </div>
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
                    {selectedFile.sandbox && (
                      <>
                        <div className="file-detail__separator" />
                        <h4 className="file-detail__section-title">Sandbox Intelligence</h4>
                        <div className="file-detail__row">
                          <span className="file-detail__label">Execution State</span>
                          <span className="file-detail__value mono text-muted">{selectedFile.sandbox.statusDetail}</span>
                        </div>
                        {selectedFile.sandbox.entropy !== null && (
                          <div className="file-detail__row">
                            <span className="file-detail__label">Heuristic Entropy</span>
                            <span className="file-detail__value mono">{selectedFile.sandbox.entropy.toFixed(4)}</span>
                          </div>
                        )}
                        {selectedFile.sandbox.flags && selectedFile.sandbox.flags.length > 0 && (
                          <div className="file-detail__row" style={{ alignItems: 'flex-start' }}>
                            <span className="file-detail__label">Threat Indicators</span>
                            <div className="file-detail__value">
                              <ul style={{ margin: 0, paddingLeft: '1rem', color: 'var(--color-threat)', fontSize: '0.85rem' }}>
                                {selectedFile.sandbox.flags.map((f, i) => <li key={i}>{f}</li>)}
                              </ul>
                            </div>
                          </div>
                        )}
                        {selectedFile.sandbox.traceLog && (
                          <div style={{ marginTop: '1rem' }}>
                            <span className="file-detail__label" style={{ display: 'block', marginBottom: '0.5rem' }}>Execution Trace Monitor (strace)</span>
                            <div className="code-block" style={{ maxHeight: '200px', overflowY: 'auto', fontSize: '0.75rem', padding: '0.5rem', background: '#0d1117', border: '1px solid #30363d', borderRadius: '4px' }}>
                              <pre style={{ margin: 0, color: '#e6edf3', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}><code>{selectedFile.sandbox.traceLog}</code></pre>
                            </div>
                          </div>
                        )}
                      </>
                    )}
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

      <Modal
        isOpen={showIntegrityModal}
        onClose={() => setShowIntegrityModal(false)}
        title="⚠ Security Warning"
        actions={
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', width: '100%' }}>
            <button className="btn btn-secondary" onClick={() => setShowIntegrityModal(false)}>
              Cancel Download
            </button>
            <button className="btn btn-danger" onClick={() => handleDownload(integrityFailedFile, true)}>
              Download Recovery Copy
            </button>
          </div>
        }
      >
        <div style={{ color: 'var(--text-primary)', padding: '10px 0' }}>
          <p style={{ fontWeight: '600', color: 'var(--color-threat, #ef4444)', marginBottom: '14px', fontSize: '1.05rem' }}>
            This file failed integrity verification.
          </p>
          <p style={{ fontSize: '0.9rem', marginBottom: '12px' }}>Possible causes:</p>
          <ul style={{ margin: '0 0 16px 0', paddingLeft: '20px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ marginBottom: '6px' }}>• Storage corruption</li>
            <li style={{ marginBottom: '6px' }}>• Accidental modification</li>
            <li style={{ marginBottom: '6px' }}>• Unauthorized tampering</li>
          </ul>
          <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
            The file can no longer be considered trustworthy.
          </p>
          {integrityReasons.length > 0 && (
            <div style={{ marginTop: '16px', padding: '10px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '6px' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 'bold', color: 'var(--color-threat, #ef4444)', display: 'block', marginBottom: '4px' }}>Failure Reasons:</span>
              <ul style={{ margin: 0, paddingLeft: '14px', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                {integrityReasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
