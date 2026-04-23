import { useState, useRef, useCallback } from 'react';
import { UploadCloud, Lock, AlertCircle, Zap, CheckCircle2 } from 'lucide-react';
import './UploadZone.css';

export default function UploadZone({ onUpload, disabled = false, useApi = false }) {
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [fileName, setFileName] = useState('');
  const [uploadPhase, setUploadPhase] = useState(''); // 'preparing' | 'uploading' | 'finalizing'
  const [uploadSpeed, setUploadSpeed] = useState('');
  const fileInputRef = useRef(null);
  const speedTracker = useRef({ startTime: 0, lastTime: 0, lastLoaded: 0 });

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    if (!disabled && !uploading) setDragOver(true);
  }, [disabled, uploading]);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const formatSpeed = (bytesPerSecond) => {
    if (bytesPerSecond < 1024) return `${bytesPerSecond.toFixed(0)} B/s`;
    const kb = bytesPerSecond / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB/s`;
    const mb = kb / 1024;
    return `${mb.toFixed(1)} MB/s`;
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    const mb = kb / 1024;
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    return `${(mb / 1024).toFixed(1)} GB`;
  };

  const validateFile = (file) => {
    if (!file.name.endsWith('.zip')) {
      setError('Only .zip files are accepted.');
      setTimeout(() => setError(''), 3000);
      return false;
    }
    if (file.size > 500 * 1024 * 1024) {
      setError('File exceeds 500MB limit.');
      setTimeout(() => setError(''), 3000);
      return false;
    }
    return true;
  };

  const doUpload = async (file) => {
    setUploading(true);
    setFileName(file.name);
    setProgress(0);
    setError('');
    setUploadPhase('preparing');
    setUploadSpeed('');
    speedTracker.current = { startTime: Date.now(), lastTime: Date.now(), lastLoaded: 0 };

    if (useApi) {
      // Real API multipart upload with progress
      try {
        setUploadPhase('uploading');
        await onUpload(file, (pct) => {
          setProgress(pct);

          // Calculate upload speed
          const now = Date.now();
          const elapsed = (now - speedTracker.current.lastTime) / 1000;
          if (elapsed >= 0.5) { // Update speed every 500ms
            const loaded = (pct / 100) * file.size;
            const bytesPerSecond = (loaded - speedTracker.current.lastLoaded) / elapsed;
            if (bytesPerSecond > 0) {
              setUploadSpeed(formatSpeed(bytesPerSecond));
            }
            speedTracker.current.lastTime = now;
            speedTracker.current.lastLoaded = loaded;
          }

          if (pct >= 99) {
            setUploadPhase('finalizing');
          }
        });
        setProgress(100);
        setUploadPhase('');
        setSuccess(true);
        setTimeout(() => {
          setSuccess(false);
          setUploading(false);
          setProgress(0);
          setFileName('');
          setUploadSpeed('');
        }, 1000);
      } catch (err) {
        setError(err.message || 'Upload failed');
        setUploadPhase('');
        setTimeout(() => setError(''), 5000);
        setUploading(false);
        setProgress(0);
        setFileName('');
        setUploadSpeed('');
      }
    } else {
      // Simulated (fallback)
      let p = 0;
      const interval = setInterval(() => {
        p += Math.random() * 15 + 5;
        if (p >= 100) {
          p = 100;
          clearInterval(interval);
          setProgress(100);
          setTimeout(() => {
            setSuccess(true);
            setUploading(false);
            setTimeout(() => {
              setSuccess(false);
              setProgress(0);
              setFileName('');
              if (onUpload) onUpload(file);
            }, 800);
          }, 300);
        } else {
          setProgress(Math.min(p, 99));
        }
      }, 100);
    }
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    if (disabled || uploading) return;

    const file = e.dataTransfer.files[0];
    if (file && validateFile(file)) {
      doUpload(file);
    }
  }, [disabled, uploading, onUpload, useApi]);

  const handleClick = () => {
    if (!disabled && !uploading) fileInputRef.current?.click();
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file && validateFile(file)) {
      doUpload(file);
    }
    e.target.value = '';
  };

  const getPhaseLabel = () => {
    switch (uploadPhase) {
      case 'preparing': return 'Preparing multipart upload...';
      case 'uploading': return uploadSpeed ? `Uploading at ${uploadSpeed}` : 'Uploading chunks to S3...';
      case 'finalizing': return 'Assembling in quarantine zone...';
      default: return '';
    }
  };

  return (
    <div
      className={`upload-zone ${dragOver ? 'upload-zone--dragover' : ''} ${uploading ? 'upload-zone--uploading' : ''} ${error ? 'upload-zone--error' : ''} ${success ? 'upload-zone--success' : ''} ${disabled ? 'upload-zone--disabled' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
      id="upload-zone"
    >
      <input
        type="file"
        ref={fileInputRef}
        accept=".zip"
        onChange={handleFileSelect}
        style={{ display: 'none' }}
      />

      {success && <div className="upload-zone__success-flash" />}

      {disabled ? (
        <div className="upload-zone__content">
          <Lock size={48} className="upload-zone__icon upload-zone__icon--locked" />
          <p className="upload-zone__text">Connect your AWS account to start uploading</p>
          <span className="upload-zone__hint">Go to Settings → Connect with AWS</span>
        </div>
      ) : uploading ? (
        <div className="upload-zone__content">
          <div className="upload-zone__upload-header">
            {uploadPhase === 'finalizing' ? (
              <CheckCircle2 size={20} className="upload-zone__phase-icon upload-zone__phase-icon--finalizing" />
            ) : (
              <Zap size={20} className="upload-zone__phase-icon upload-zone__phase-icon--streaming" />
            )}
            <p className="upload-zone__filename">{fileName}</p>
          </div>
          <div className="upload-zone__progress-bar">
            <div className="upload-zone__progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <div className="upload-zone__progress-info">
            <span className="upload-zone__progress-text">{Math.round(progress)}% uploaded</span>
            {uploadPhase && (
              <span className="upload-zone__phase-text">{getPhaseLabel()}</span>
            )}
          </div>
        </div>
      ) : (
        <div className="upload-zone__content">
          <UploadCloud size={48} className="upload-zone__icon" />
          <p className="upload-zone__text">
            Drag & drop your ZIP file here
          </p>
          <span className="upload-zone__hint">or click to browse · Max 500MB · ZIP only</span>
          <span className="upload-zone__hint upload-zone__hint--speed">
            <Zap size={12} /> Direct-to-S3 multipart upload · Parallel chunks
          </span>
        </div>
      )}

      {error && (
        <div className="upload-zone__error">
          <AlertCircle size={14} />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
