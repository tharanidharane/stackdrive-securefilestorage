import { Fingerprint, Archive, Bug, Box, Lock } from 'lucide-react';
import StatusBadge from './StatusBadge';
import './PipelinePanel.css';

const stageIcons = {
  'SHA-256 + VirusTotal': Fingerprint,
  'ZIP Heuristic Analysis': Archive,
  'ClamAV (Docker)': Bug,
  'Sandbox (Docker)': Box,
  'Encryption': Lock,
};

export default function PipelinePanel({ isActive, fileName, stages, result, showBanner }) {
  if (!isActive) return null;

  return (
    <div className="pipeline-panel" id="security-pipeline-panel">
      <h2 className="pipeline-panel__title">Security Pipeline</h2>
      {fileName && <p className="pipeline-panel__file">{fileName}</p>}

      <div className="pipeline-panel__stages">
        {stages.map((stage, index) => {
          const Icon = stageIcons[stage.name] || Lock;
          const isLast = index === stages.length - 1;
          const dotClass = 
            stage.status === 'pass' ? 'pipeline-dot--pass' :
            stage.status === 'running' ? 'pipeline-dot--running' :
            stage.status === 'fail' ? 'pipeline-dot--fail' :
            'pipeline-dot--pending';

          return (
            <div key={stage.name} className="pipeline-stage">
              <div className="pipeline-stage__indicator">
                <div className={`pipeline-dot ${dotClass}`}>
                  {(stage.status === 'pass' || stage.status === 'fail' || stage.status === 'running') ? '●' : '○'}
                </div>
                {!isLast && <div className="pipeline-connector" />}
              </div>

              <div className="pipeline-stage__content">
                <div className="pipeline-stage__header">
                  <div className="pipeline-stage__label">
                    <Icon size={16} className="pipeline-stage__icon" style={{
                      color: stage.status === 'pass' ? 'var(--color-pass)' :
                             stage.status === 'fail' ? 'var(--color-threat)' :
                             stage.status === 'running' ? 'var(--color-scan)' :
                             'var(--text-muted)'
                    }} />
                    <span className="pipeline-stage__name">{stage.name}</span>
                  </div>
                  <StatusBadge status={stage.status} small />
                </div>
                <p className="pipeline-stage__detail">{stage.statusDetail || stage.detail}</p>
              </div>
            </div>
          );
        })}
      </div>

      {showBanner && result && (
        <div className={`pipeline-banner ${result === 'safe' ? 'pipeline-banner--safe' : 'pipeline-banner--blocked'}`}>
          {result === 'safe' ? '✓ FILE VERIFIED — SAFE' : '✗ FILE REJECTED — BLOCKED'}
        </div>
      )}
    </div>
  );
}
