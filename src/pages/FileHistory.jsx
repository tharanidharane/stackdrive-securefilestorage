import { useState, useEffect, useCallback } from 'react';
import FileTable from '../components/FileTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import { useToast } from '../components/Toast';
import api from '../services/api';
import './FileHistory.css';

const filterTabs = ['all', 'safe', 'blocked', 'scanning', 'quarantine'];

export default function FileHistory() {
  const [activeFilter, setActiveFilter] = useState('all');
  const [files, setFiles] = useState([]);
  const [allFiles, setAllFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showDetail, setShowDetail] = useState(false);
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
        onClose={() => setShowDetail(false)}
        title="File Details"
        actions={
          <>
            {selectedFile?.status === 'safe' && (
              <button className="btn btn-primary" style={{ width: 'auto' }}
                onClick={() => handleDownload(selectedFile)}>
                Download
              </button>
            )}
            <button className="btn btn-danger" style={{ width: 'auto' }}
              onClick={() => handleDelete(selectedFile)}>
              Delete
            </button>
            <button className="btn btn-secondary" onClick={() => setShowDetail(false)}>
              Close
            </button>
          </>
        }
      >
        {selectedFile && (
          <div className="file-detail">
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
          </div>
        )}
      </Modal>
    </div>
  );
}
