/**
 * StackDrive API Service
 * Handles all communication with the Flask backend
 */

const API_BASE = 'http://localhost:5000/api';

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

  // ── Upload ────────────────────────────
  async uploadFile(file, onProgress) {
    const formData = new FormData();
    formData.append('file', file);

    const url = `${API_BASE}/upload`;
    const token = this.getToken();

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      });

      xhr.addEventListener('load', () => {
        try {
          const data = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(data);
          } else {
            reject(new ApiError(data.error || 'Upload failed', xhr.status));
          }
        } catch {
          reject(new ApiError('Upload failed', xhr.status));
        }
      });

      xhr.addEventListener('error', () => reject(new ApiError('Network error', 0)));
      xhr.send(formData);
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
