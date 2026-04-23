/**
 * StackDrive API Service
 * Handles all communication with the Flask backend
 * 
 * Upload strategy: S3 Presigned Multipart Upload
 * - Files are uploaded directly from the browser to S3 in parallel chunks
 * - This bypasses the Flask server completely for the data transfer
 * - 500MB files upload in seconds instead of minutes
 */

const API_BASE = 'http://localhost:5000/api';

// Upload configuration
const MAX_CONCURRENT_CHUNKS = 6;   // Max parallel chunk uploads (browser limit per domain)
const MAX_RETRY_ATTEMPTS = 3;      // Retry failed chunks up to 3 times
const RETRY_DELAY_MS = 1000;       // Base retry delay (exponential backoff)

class ApiService {
  constructor() {
    this.token = localStorage.getItem('stackdrive_token') || null;
  }

  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('stackdrive_token', token);
    } else {
      localStorage.removeItem('stackdrive_token');
    }
  }

  getToken() {
    return this.token || localStorage.getItem('stackdrive_token');
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = { ...options.headers };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, { ...options, headers });
    const data = await response.json();

    if (!response.ok) {
      if (response.status === 401) {
        // Session expired
        this.setToken(null);
        window.dispatchEvent(new CustomEvent('auth:expired'));
      }
      throw new ApiError(data.error || 'Request failed', response.status);
    }

    return data;
  }

  // ── Auth ──────────────────────────────
  async signup(email, password) {
    const data = await this.request('/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.token);
    return data;
  }

  async login(email, password) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.token);
    return data;
  }

  async getMe() {
    return this.request('/auth/me');
  }

  logout() {
    this.setToken(null);
    localStorage.removeItem('stackdrive_session');
  }

  // ── AWS ───────────────────────────────
  async connectAws(credentials) {
    return this.request('/aws/connect', { 
        method: 'POST',
        body: JSON.stringify(credentials)
    });
  }

  async getAwsStatus() {
    return this.request('/aws/status');
  }

  async disconnectAws() {
    return this.request('/aws/disconnect', { method: 'POST' });
  }

  // ── Upload (Presigned Multipart — Direct to S3) ────────────
  /**
   * Upload a file using S3 presigned multipart upload.
   * 
   * Flow:
   *   1. POST /api/upload/initiate → get presigned URLs for each chunk
   *   2. PUT each chunk directly to S3 via presigned URLs (parallel, up to 6 at a time)
   *   3. POST /api/upload/complete → assemble chunks in S3, start pipeline
   * 
   * @param {File} file - The file to upload
   * @param {Function} onProgress - Progress callback (0-100)
   * @returns {Promise<Object>} - Upload result with file record
   */
  async uploadFile(file, onProgress) {
    // ── Step 1: Initiate multipart upload ──
    const initData = await this.request('/upload/initiate', {
      method: 'POST',
      body: JSON.stringify({
        fileName: file.name,
        fileSize: file.size,
      }),
    });

    const { uploadId, fileId, s3Key, chunkSize, totalParts, presignedUrls } = initData;

    try {
      // ── Step 2: Upload chunks directly to S3 in parallel ──
      const parts = await this._uploadChunksParallel(
        file, presignedUrls, chunkSize, totalParts, onProgress
      );

      // ── Step 3: Complete multipart upload ──
      const completeData = await this.request('/upload/complete', {
        method: 'POST',
        body: JSON.stringify({
          uploadId,
          fileId,
          s3Key,
          parts,
        }),
      });

      return completeData;

    } catch (err) {
      // Abort multipart upload on failure to clean up S3 parts
      try {
        await this.request('/upload/abort', {
          method: 'POST',
          body: JSON.stringify({ uploadId, fileId, s3Key }),
        });
      } catch {
        // Ignore abort errors
      }
      throw err;
    }
  }

  /**
   * Upload file chunks in parallel with concurrency control.
   * Uses a pool of MAX_CONCURRENT_CHUNKS workers for maximum throughput.
   */
  async _uploadChunksParallel(file, presignedUrls, chunkSize, totalParts, onProgress) {
    const parts = new Array(totalParts);
    const chunkProgress = new Array(totalParts).fill(0);
    let completedChunks = 0;

    const updateTotalProgress = () => {
      // Weighted progress: each chunk contributes proportionally
      const totalLoaded = chunkProgress.reduce((sum, p, i) => {
        const start = i * chunkSize;
        const end = Math.min(start + chunkSize, file.size);
        const thisChunkSize = end - start;
        return sum + (p / 100) * thisChunkSize;
      }, 0);
      const pct = Math.round((totalLoaded / file.size) * 100);
      if (onProgress) onProgress(Math.min(pct, 99)); // Cap at 99 until complete
    };

    // Worker function that processes one chunk
    const uploadChunk = async (partIndex) => {
      const partNumber = partIndex + 1;
      const start = partIndex * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      const blob = file.slice(start, end);
      const url = presignedUrls[partIndex];

      // Retry loop with exponential backoff
      for (let attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        try {
          const etag = await this._uploadSingleChunk(url, blob, (pct) => {
            chunkProgress[partIndex] = pct;
            updateTotalProgress();
          });

          parts[partIndex] = { PartNumber: partNumber, ETag: etag };
          completedChunks++;
          return;

        } catch (err) {
          if (attempt < MAX_RETRY_ATTEMPTS - 1) {
            // Exponential backoff: 1s, 2s, 4s
            const delay = RETRY_DELAY_MS * Math.pow(2, attempt);
            await new Promise(r => setTimeout(r, delay));
            chunkProgress[partIndex] = 0; // Reset progress for retry
          } else {
            throw new ApiError(
              `Chunk ${partNumber}/${totalParts} failed after ${MAX_RETRY_ATTEMPTS} attempts: ${err.message}`,
              0
            );
          }
        }
      }
    };

    // Concurrency-limited execution pool
    const queue = Array.from({ length: totalParts }, (_, i) => i);
    const workers = [];

    const runWorker = async () => {
      while (queue.length > 0) {
        const idx = queue.shift();
        await uploadChunk(idx);
      }
    };

    // Spawn workers up to concurrency limit
    const workerCount = Math.min(MAX_CONCURRENT_CHUNKS, totalParts);
    for (let i = 0; i < workerCount; i++) {
      workers.push(runWorker());
    }

    await Promise.all(workers);

    if (onProgress) onProgress(100);
    return parts;
  }

  /**
   * Upload a single chunk via presigned PUT URL.
   * Returns the ETag from S3 (required for multipart completion).
   */
  _uploadSingleChunk(presignedUrl, blob, onChunkProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', presignedUrl);

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable && onChunkProgress) {
          onChunkProgress(Math.round((e.loaded / e.total) * 100));
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          // S3 returns ETag in response header
          const etag = xhr.getResponseHeader('ETag');
          if (!etag) {
            reject(new Error('S3 did not return ETag header'));
            return;
          }
          resolve(etag);
        } else {
          reject(new Error(`S3 PUT failed with status ${xhr.status}`));
        }
      });

      xhr.addEventListener('error', () => reject(new Error('Network error during chunk upload')));
      xhr.addEventListener('timeout', () => reject(new Error('Chunk upload timed out')));

      // 5 minute timeout per chunk (generous for large chunks on slow connections)
      xhr.timeout = 5 * 60 * 1000;
      xhr.send(blob);
    });
  }

  // ── Files ─────────────────────────────
  async getFiles(status) {
    const params = status && status !== 'all' ? `?status=${status}` : '';
    return this.request(`/files${params}`);
  }

  async getFile(fileId) {
    return this.request(`/files/${fileId}`);
  }

  async downloadFile(fileId) {
    const url = `${API_BASE}/files/${fileId}/download`;
    const token = this.getToken();
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new ApiError('Download failed', response.status);
    const blob = await response.blob();
    return blob;
  }

  async deleteFile(fileId) {
    return this.request(`/files/${fileId}`, { method: 'DELETE' });
  }

  // ── Pipeline ──────────────────────────
  async getPipeline(fileId) {
    return this.request(`/pipeline/${fileId}`);
  }

  // ── Dashboard ─────────────────────────
  async getDashboardMetrics() {
    return this.request('/dashboard/metrics');
  }

  // ── Notifications ─────────────────────
  async getNotifications() {
    return this.request('/notifications');
  }

  async markNotificationsRead() {
    return this.request('/notifications/read', { method: 'POST' });
  }

  // ── Security ──────────────────────────
  async getSecurityStats() {
    return this.request('/security/stats');
  }
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

// Singleton instance
const api = new ApiService();
export default api;
export { ApiError };
