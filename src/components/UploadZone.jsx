import { useState, useRef, useCallback } from 'react';
import { UploadCloud, Lock, AlertCircle } from 'lucide-react';
import './UploadZone.css';

export default function UploadZone({ onUpload, disabled = false, useApi = false }) {
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [fileName, setFileName] = useState('');
  const fileInputRef = useRef(null);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    if (!disabled && !uploading) setDragOver(true);
  }, [disabled, uploading]);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

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

    if (useApi) {
      // Real API upload with XHR progress
      try {
        await onUpload(file, (pct) => setProgress(pct));
        setProgress(100);
        setSuccess(true);
        setTimeout(() => {
          setSuccess(false);
          setUploading(false);
          setProgress(0);
          setFileName('');
        }, 1000);
      } catch (err) {
        setError(err.message || 'Upload failed');
        setTimeout(() => setError(''), 3000);
        setUploading(false);
        setProgress(0);
        setFileName('');
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
          <p className="upload-zone__filename">{fileName}</p>
          <div className="upload-zone__progress-bar">
            <div className="upload-zone__progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <span className="upload-zone__progress-text">{Math.round(progress)}% uploaded</span>
        </div>
      ) : (
        <div className="upload-zone__content">
          <UploadCloud size={48} className="upload-zone__icon" />
          <p className="upload-zone__text">
            Drag & drop your ZIP file here
          </p>
          <span className="upload-zone__hint">or click to browse · Max 500MB · ZIP only</span>
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
