import { FolderOpen } from 'lucide-react';
import StatusBadge from './StatusBadge';
import './FileTable.css';

function getRelativeTime(dateInput) {
  const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function FileTable({ files, loading = false, onRowClick, compact = false }) {
  if (loading) {
    return (
      <div className="file-table-wrapper">
        <div className="file-table__skeleton">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="skeleton skeleton-row" />
          ))}
        </div>
      </div>
    );
  }

  if (!files?.length) {
    return (
      <div className="empty-state">
        <FolderOpen size={48} />
        <h3>No files uploaded yet</h3>
        <p>Start by dropping a ZIP file in the upload zone above.</p>
      </div>
    );
  }

  return (
    <div className="file-table-wrapper">
      <table className="file-table" id="file-history-table">
        <thead>
          <tr>
            <th style={{ width: '32%' }}>FILE</th>
            <th style={{ width: '10%' }}>SIZE</th>
            <th style={{ width: '14%' }}>UPLOADED</th>
            <th style={{ width: '14%' }}>STATUS</th>
            <th style={{ width: '10%' }}>RISK</th>
            <th style={{ width: '20%' }}>CHECKS</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file, index) => (
            <tr
              key={file.id}
              className={`file-table__row ${file.status === 'blocked' ? 'file-table__row--blocked' : ''} ${index === 0 && !compact ? 'file-table__row--new' : ''}`}
              onClick={() => onRowClick?.(file)}
              style={{ cursor: onRowClick ? 'pointer' : 'default' }}
            >
              <td className="file-table__name">{file.name}</td>
              <td className="file-table__size">{file.size} {file.sizeUnit || 'MB'}</td>
              <td className="file-table__time" title={typeof file.uploadedAt === 'string' ? file.uploadedAt : file.uploadedAt?.toISOString?.()}>
                {getRelativeTime(file.uploadedAt)}
              </td>
              <td>
                <StatusBadge status={file.status} />
              </td>
              <td className="file-table__risk">
                {file.risk !== null && file.risk !== undefined ? (
                  <span className={`file-table__risk-value ${
                    file.risk < 10 ? 'text-safe' :
                    file.risk <= 60 ? 'text-queue' : 'text-threat'
                  }`}>
                    {file.risk}%
                  </span>
                ) : (
                  <span className="text-muted">—</span>
                )}
              </td>
              <td className="file-table__checks">
                <span className={
                  typeof file.checks === 'string' && (
                    file.checks.includes('Malware') ||
                    file.checks.includes('flagged') ||
                    file.checks.includes('bomb') ||
                    file.checks.includes('Trojan') ||
                    file.checks.includes('Backdoor') ||
                    file.checks.includes('Ransom')
                  ) ? 'text-threat' : ''
                }>
                  {file.checks}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
