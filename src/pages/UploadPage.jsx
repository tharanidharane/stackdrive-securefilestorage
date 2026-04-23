import { useState, useCallback, useRef } from 'react';
import UploadZone from '../components/UploadZone';
import PipelinePanel from '../components/PipelinePanel';
import { useToast } from '../components/Toast';
import api from '../services/api';
import './UploadPage.css';

export default function UploadPage({ user }) {
  const { addToast } = useToast();
  const [recentUploads, setRecentUploads] = useState([]);
  const [pipelineActive, setPipelineActive] = useState(false);
  const [pipelineData, setPipelineData] = useState({ stages: [], fileName: '', result: null, showBanner: false });
  const pollingRef = useRef(null);
  const awsConnected = user?.aws_connected !== false;

  const pollPipeline = useCallback(async (fileId, fileName) => {
    setPipelineActive(true);
    setPipelineData({ stages: [], fileName, result: null, showBanner: false, isActive: true });

    const poll = async () => {
      try {
        const data = await api.getPipeline(fileId);
        const stages = data.stages || [];
        const fileStatus = data.status;
        const isComplete = fileStatus === 'safe' || fileStatus === 'blocked';
        const result = fileStatus === 'safe' ? 'safe' : fileStatus === 'blocked' ? 'blocked' : null;

        setPipelineData({ stages, fileName, result, showBanner: isComplete, isActive: true });

        if (isComplete) {
          clearInterval(pollingRef.current);
          pollingRef.current = null;

          setRecentUploads(prev => prev.map(u =>
            u.fileId === fileId ? { ...u, status: fileStatus } : u
          ));

          if (fileStatus === 'safe') {
            addToast(`${fileName} verified and stored securely`, 'success');
          } else {
            addToast(`Threat detected in ${fileName}`, 'error');
          }
          setTimeout(() => setPipelineActive(false), 6000);
        }
      } catch { /* keep polling */ }
    };

    await poll();
    pollingRef.current = setInterval(poll, 1500);
  }, [addToast]);

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    const mb = kb / 1024;
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    return `${(mb / 1024).toFixed(1)} GB`;
  };

  const handleUpload = useCallback(async (file, progressCallback) => {
    try {
      const data = await api.uploadFile(file, progressCallback);
      const upload = {
        id: Date.now(),
        fileId: data.file?.id,
        name: file.name,
        size: formatFileSize(file.size),
        time: new Date().toLocaleTimeString(),
        status: 'scanning',
      };
      setRecentUploads(prev => [upload, ...prev]);
      addToast(`${file.name} uploaded — pipeline starting`, 'info');

      if (data.file?.id) {
        pollPipeline(data.file.id, file.name);
      }
    } catch (err) {
      addToast(err.message || 'Upload failed', 'error');
    }
  }, [addToast, pollPipeline]);

  return (
    <>
      <div className="content-area">
        <div className="upload-page stagger-1">
          <div className="upload-page__header">
            <h2 className="section-title">Upload File</h2>
            <p className="upload-page__desc">
              Drop your ZIP file below. It will be quarantined and scanned through our 4-layer security pipeline before being encrypted and stored in your AWS S3 bucket.
            </p>
          </div>

          <div className="upload-page__zone">
            <UploadZone onUpload={handleUpload} disabled={!awsConnected} useApi={true} />
          </div>

          <div className="upload-page__info">
            <div className="upload-info-card">
              <h4>Accepted Format</h4>
              <p>.zip files only</p>
            </div>
            <div className="upload-info-card">
              <h4>Max File Size</h4>
              <p>500 MB per upload</p>
            </div>
            <div className="upload-info-card">
              <h4>Security Layers</h4>
              <p>4 automated checks</p>
            </div>
            <div className="upload-info-card">
              <h4>Encryption</h4>
              <p>AES-256 + Kyber PQ</p>
            </div>
          </div>

          {recentUploads.length > 0 && (
            <div className="upload-page__recent stagger-2">
              <h3 className="section-title" style={{ fontSize: 'var(--text-lg)' }}>This Session</h3>
              <div className="recent-uploads">
                {recentUploads.map(upload => (
                  <div key={upload.id} className="recent-upload-item">
                    <span className="recent-upload-name mono">{upload.name}</span>
                    <span className="recent-upload-size">{upload.size}</span>
                    <span className="recent-upload-time">{upload.time}</span>
                    <span className={`recent-upload-status ${
                      upload.status === 'safe' ? 'text-safe' :
                      upload.status === 'blocked' ? 'text-threat' : 'text-scan'
                    }`}>
                      {upload.status.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {pipelineActive && (
        <div className="right-panel">
          <PipelinePanel {...pipelineData} />
        </div>
      )}
    </>
  );
}
