import { useState, useEffect, useCallback, useRef } from 'react';
import { ShieldCheck, ShieldX, ScanLine, Clock } from 'lucide-react';
import StatCard from '../components/StatCard';
import UploadZone from '../components/UploadZone';
import FileTable from '../components/FileTable';
import PipelinePanel from '../components/PipelinePanel';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';
import { useToast } from '../components/Toast';
import api from '../services/api';
import './Dashboard.css';

export default function Dashboard({ user }) {
  const [files, setFiles] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showDetail, setShowDetail] = useState(false);
  const [pipelineActive, setPipelineActive] = useState(false);
  const [pipelineData, setPipelineData] = useState({ stages: [], fileName: '', result: null, showBanner: false });
  const { addToast } = useToast();
  const pollingRef = useRef(null);

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

  // Poll pipeline status for a file
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

        setPipelineData({
          stages,
          fileName,
          result,
          showBanner: isComplete,
          isActive: true,
        });

        if (isComplete) {
          clearInterval(pollingRef.current);
          pollingRef.current = null;
          fetchData(); // Refresh dashboard

          if (fileStatus === 'safe') {
            addToast(`${fileName} verified and stored securely`, 'success');
          } else {
            addToast(`Threat blocked in ${fileName}`, 'error');
          }

          // Auto-hide pipeline after 6s
          setTimeout(() => setPipelineActive(false), 6000);
        }
      } catch (err) {
        // Keep polling
      }
    };

    // Initial check
    await poll();
    pollingRef.current = setInterval(poll, 1500);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchData, addToast]);

  const handleUpload = useCallback(async (file, progressCallback) => {
    try {
      const data = await api.uploadFile(file, progressCallback);
      addToast(`${file.name} uploaded to quarantine`, 'info');
      fetchData();

      // Start polling pipeline
      if (data.file?.id) {
        pollPipeline(data.file.id, file.name);
      }
    } catch (err) {
      addToast(err.message || 'Upload failed', 'error');
    }
  }, [addToast, fetchData, pollPipeline]);

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

        {/* Upload Zone */}
        <div className="stagger-2">
          <UploadZone onUpload={handleUpload} disabled={!awsConnected} useApi={true} />
        </div>

        {/* Recent File History */}
        <div className="stagger-3">
          <h2 className="section-title" style={{ marginTop: 'var(--space-8)' }}>Recent Files</h2>
          <FileTable
            files={files.slice(0, 7)}
            loading={loading}
            onRowClick={handleRowClick}
          />
        </div>
      </div>

      {/* Right Pipeline Panel */}
      {pipelineActive && (
        <div className="right-panel">
          <PipelinePanel {...pipelineData} />
        </div>
      )}

      {/* File Detail Modal */}
      <Modal
        isOpen={showDetail}
        onClose={() => setShowDetail(false)}
        title="File Details"
        actions={
          selectedFile?.status === 'safe' ? (
            <button className="btn btn-primary" style={{ width: 'auto' }}
              onClick={() => handleDownload(selectedFile)}>
              Download File
            </button>
          ) : null
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
    </>
  );
}
