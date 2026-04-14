// Mock data for StackDrive dashboard demo
export const mockFiles = [
  {
    id: 'f001',
    name: 'quarterly-report-2026.zip',
    size: 24.3,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 2 * 60 * 1000),
    status: 'safe',
    risk: 0,
    checks: '4/4 complete',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'pass', detail: 'No threats detected' },
      { name: 'Sandbox Analysis', status: 'pass', detail: 'No suspicious behavior' },
      { name: 'Encryption', status: 'pass', detail: 'AES-256 + Kyber PQ applied' },
    ],
  },
  {
    id: 'f002',
    name: 'client-assets-v3.zip',
    size: 156.7,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 15 * 60 * 1000),
    status: 'safe',
    risk: 2,
    checks: '4/4 complete',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'pass', detail: 'No threats detected' },
      { name: 'Sandbox Analysis', status: 'pass', detail: 'Minor file system access — benign' },
      { name: 'Encryption', status: 'pass', detail: 'AES-256 + Kyber PQ applied' },
    ],
  },
  {
    id: 'f003',
    name: 'payload-dropper.zip',
    size: 8.1,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 45 * 60 * 1000),
    status: 'blocked',
    risk: 95,
    checks: 'Malware detected',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'fail', detail: 'Trojan.GenericKD.46542 detected' },
      { name: 'Sandbox Analysis', status: 'skipped', detail: 'Skipped — prior layer failed' },
      { name: 'Encryption', status: 'skipped', detail: 'Skipped — file rejected' },
    ],
  },
  {
    id: 'f004',
    name: 'deployment-bundle.zip',
    size: 42.0,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 3 * 60 * 1000),
    status: 'scanning',
    risk: null,
    checks: '2/4 complete',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'running', detail: 'Deep antivirus scan in progress...' },
      { name: 'Sandbox Analysis', status: 'pending', detail: 'Waiting for ClamAV to complete' },
      { name: 'Encryption', status: 'pending', detail: 'Will encrypt with AES-256 + Kyber PQ' },
    ],
  },
  {
    id: 'f005',
    name: 'firmware-update-v2.1.zip',
    size: 18.4,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 1 * 60 * 1000),
    status: 'quarantine',
    risk: null,
    checks: 'Awaiting scan',
    pipelineStages: [
      { name: 'Hash Check', status: 'pending', detail: 'Awaiting pipeline slot' },
      { name: 'ZIP Validation', status: 'pending', detail: 'Pending' },
      { name: 'ClamAV Scan', status: 'pending', detail: 'Pending' },
      { name: 'Sandbox Analysis', status: 'pending', detail: 'Pending' },
      { name: 'Encryption', status: 'pending', detail: 'Pending' },
    ],
  },
  {
    id: 'f006',
    name: 'marketing-collateral.zip',
    size: 89.2,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    status: 'safe',
    risk: 1,
    checks: '4/4 complete',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'pass', detail: 'No threats detected' },
      { name: 'Sandbox Analysis', status: 'pass', detail: 'No suspicious behavior' },
      { name: 'Encryption', status: 'pass', detail: 'AES-256 + Kyber PQ applied' },
    ],
  },
  {
    id: 'f007',
    name: 'ransomware-sample.zip',
    size: 3.4,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 3 * 60 * 60 * 1000),
    status: 'blocked',
    risk: 99,
    checks: 'Sandbox flagged',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'pass', detail: 'No signature match' },
      { name: 'Sandbox Analysis', status: 'fail', detail: 'Privilege escalation attempt detected' },
      { name: 'Encryption', status: 'skipped', detail: 'Skipped — file rejected' },
    ],
  },
  {
    id: 'f008',
    name: 'database-backup-apr.zip',
    size: 312.5,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
    status: 'safe',
    risk: 0,
    checks: '4/4 complete',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'pass', detail: 'No threats detected' },
      { name: 'Sandbox Analysis', status: 'pass', detail: 'No suspicious behavior' },
      { name: 'Encryption', status: 'pass', detail: 'AES-256 + Kyber PQ applied' },
    ],
  },
  {
    id: 'f009',
    name: 'zipbomb-test.zip',
    size: 0.04,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
    status: 'blocked',
    risk: 87,
    checks: 'ZIP bomb detected',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'fail', detail: 'ZIP bomb detected — decompression ratio 1:1000000' },
      { name: 'ClamAV Scan', status: 'skipped', detail: 'Skipped — prior layer failed' },
      { name: 'Sandbox Analysis', status: 'skipped', detail: 'Skipped — prior layer failed' },
      { name: 'Encryption', status: 'skipped', detail: 'Skipped — file rejected' },
    ],
  },
  {
    id: 'f010',
    name: 'project-alpha-src.zip',
    size: 67.8,
    sizeUnit: 'MB',
    uploadedAt: new Date(Date.now() - 48 * 60 * 60 * 1000),
    status: 'safe',
    risk: 3,
    checks: '4/4 complete',
    pipelineStages: [
      { name: 'Hash Check', status: 'pass', detail: 'No known malware signature' },
      { name: 'ZIP Validation', status: 'pass', detail: 'Archive structure valid' },
      { name: 'ClamAV Scan', status: 'pass', detail: 'No threats detected' },
      { name: 'Sandbox Analysis', status: 'pass', detail: 'Minor network probe — benign' },
      { name: 'Encryption', status: 'pass', detail: 'AES-256 + Kyber PQ applied' },
    ],
  },
];

export const dashboardMetrics = {
  filesSafe: { value: 1247, today: 2, label: 'Files Safe', sublabel: '+2 today' },
  threatsBlocked: { value: 38, today: 0, label: 'Threats Blocked', sublabel: 'Last: 3h ago' },
  scanningNow: { value: 3, today: 0, label: 'Scanning Now', sublabel: '~2 min remaining' },
  inQuarantine: { value: 7, today: 1, label: 'In Quarantine', sublabel: '+1 queued' },
};

export const recentThreats = [
  {
    id: 't001',
    fileName: 'payload-dropper.zip',
    detectedAt: new Date(Date.now() - 45 * 60 * 1000),
    layer: 'Layer 3 — ClamAV Scan',
    threatType: 'Trojan.GenericKD.46542',
    action: 'Deleted from quarantine',
  },
  {
    id: 't002',
    fileName: 'ransomware-sample.zip',
    detectedAt: new Date(Date.now() - 3 * 60 * 60 * 1000),
    layer: 'Layer 4 — Sandbox Analysis',
    threatType: 'Privilege escalation attempt',
    action: 'Deleted from quarantine',
  },
  {
    id: 't003',
    fileName: 'zipbomb-test.zip',
    detectedAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
    layer: 'Layer 2 — ZIP Validation',
    threatType: 'ZIP bomb (ratio 1:1000000)',
    action: 'Deleted from quarantine',
  },
];

export const securityStats = {
  totalScanned: 1292,
  passRate: 96.5,
  avgScanTime: '2m 14s',
  layerStats: [
    { name: 'Hash Check', passed: 1289, failed: 3, icon: 'Fingerprint' },
    { name: 'ZIP Validation', passed: 1286, failed: 6, icon: 'Archive' },
    { name: 'ClamAV Scan', passed: 1262, failed: 24, icon: 'Bug' },
    { name: 'Sandbox Analysis', passed: 1252, failed: 5, icon: 'Box' },
  ],
};

export function getRelativeTime(date) {
  const now = new Date();
  const diff = now - date;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString();
}

export function formatFileSize(size, unit) {
  return `${size} ${unit}`;
}
