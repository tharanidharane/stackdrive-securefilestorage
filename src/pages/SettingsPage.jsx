import { useState, useEffect } from 'react';
import { Cloud, CheckCircle, RefreshCw, LogOut, User, Mail, Calendar, Shield, Key, Server } from 'lucide-react';
import Modal from '../components/Modal';
import { useToast } from '../components/Toast';
import api from '../services/api';
import './SettingsPage.css';

export default function SettingsPage({ user, onUpdateUser, onLogout }) {
  const [awsConnected, setAwsConnected] = useState(user?.aws_connected || false);
  const [awsDetails, setAwsDetails] = useState({});
  const [connecting, setConnecting] = useState(false);
  const [provisioning, setProvisioning] = useState(false);
  const [provisionStep, setProvisionStep] = useState(0);
  const [provisionMessage, setProvisionMessage] = useState('');
  const [showDisconnect, setShowDisconnect] = useState(false);
  const { addToast } = useToast();
  const [awsForm, setAwsForm] = useState({ access_key: '', secret_key: '', region: 'ap-south-1' });

  // Fetch AWS status on mount
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const data = await api.getAwsStatus();
        setAwsConnected(data.connected);
        setAwsDetails(data);
      } catch { /* ignore */ }
    };
    fetchStatus();
  }, []);

  const handleConnect = async (e) => {
    if (e) e.preventDefault();
    if (!awsForm.access_key || !awsForm.secret_key) {
        addToast('Access Key and Secret Key are required', 'error');
        return;
    }

    setConnecting(true);
    setProvisioning(true);

    try {
        const data = await api.connectAws(awsForm);
        setProvisioning(false);
        setAwsConnected(true);
        setAwsDetails({
            connected: true,
            account_id: data.user.aws_account_id,
            region: data.user.aws_region,
            quarantine_bucket: data.user.quarantine_bucket,
            secure_bucket: data.user.secure_bucket,
            kms_key_arn: data.user.kms_key_arn,
        });
        onUpdateUser?.(data.user);
        addToast('AWS environment provisioned successfully!', 'success');
    } catch (err) {
        setProvisioning(false);
        setConnecting(false);
        addToast(err.message || 'Failed to provision AWS resources', 'error');
    }
  };



  const handleDisconnect = async () => {
    setShowDisconnect(false);
    try {
      const data = await api.disconnectAws();
      setAwsConnected(false);
      setAwsDetails({});
      onUpdateUser?.(data.user);
      addToast('AWS account disconnected', 'warning');
    } catch (err) {
      addToast(err.message || 'Failed to disconnect', 'error');
    }
  };

  // Provisioning overlay
  if (provisioning) {
    return (
      <div className="content-area">
        <div className="provision-overlay">
          <div className="provision-card">
            <div className="provision-spinner">
              <Cloud size={32} />
            </div>
            <h2 className="provision-title">Setting Up AWS Resources</h2>
            <p className="provision-subtitle">Auto-provisioning your secure infrastructure...</p>
            <div className="provision-steps" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginTop: '30px' }}>
                <div className="provision-step provision-step--active" style={{ fontSize: '18px', display: 'flex', alignItems: 'center', gap: '15px' }}>
                  <div className="provision-step__dot" style={{ transform: 'scale(1.5)' }}>
                     <span className="spinner" style={{ width: 14, height: 14 }} />
                  </div>
                  <span style={{ fontWeight: '500' }}>Provisioning Real Infrastructure via Boto3...</span>
                </div>
                <div style={{ marginTop: '20px', fontSize: '14px', color: 'var(--text-muted)' }}>
                    This usually takes 15-30 seconds depending on AWS API.
                </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="content-area">
      <div className="stagger-1">
        <h2 className="section-title">Settings</h2>
        <p className="section-subtitle">Manage your account and AWS connection</p>
      </div>

      {/* AWS Connection */}
      <div className="settings-section stagger-2">
        <h3 className="settings-section__title">
          <Cloud size={18} />
          AWS Connection
        </h3>

        {awsConnected ? (
          <div className="aws-card aws-card--connected">
            <div className="aws-card__status">
              <CheckCircle size={20} className="text-safe" />
              <span className="aws-card__status-text text-safe">Connected</span>
            </div>
            <div className="aws-card__details">
              <div className="aws-card__row">
                <span className="aws-card__label">Account ID</span>
                <span className="aws-card__value mono">{awsDetails.account_id || '123456789012'}</span>
              </div>
              <div className="aws-card__row">
                <span className="aws-card__label">Region</span>
                <span className="aws-card__value mono">{awsDetails.region || 'ap-south-1'} (Mumbai)</span>
              </div>
              <div className="aws-card__row">
                <span className="aws-card__label">Quarantine Bucket</span>
                <span className="aws-card__value mono">{awsDetails.quarantine_bucket || 'stackdrive-quarantine'}</span>
              </div>
              <div className="aws-card__row">
                <span className="aws-card__label">Secure Bucket</span>
                <span className="aws-card__value mono">{awsDetails.secure_bucket || 'stackdrive-secure'}</span>
              </div>
              <div className="aws-card__row">
                <span className="aws-card__label">KMS Key</span>
                <span className="aws-card__value mono">{awsDetails.kms_key_arn || 'arn:aws:kms:...'}</span>
              </div>
              <div className="aws-card__row">
                <span className="aws-card__label">Credentials</span>
                <span className="aws-card__value mono text-safe">STS Temporary Token (Active)</span>
              </div>
            </div>
            <button className="btn btn-secondary" onClick={() => setShowDisconnect(true)} id="reconnect-aws">
              <RefreshCw size={14} />
              Reconnect AWS
            </button>
          </div>
        ) : (
          <div className="aws-card aws-card--disconnected">
            <div className="aws-card__cta" style={{ textAlign: 'left', alignItems: 'flex-start' }}>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Cloud size={20} className="aws-card__cta-icon" /> 
                  Connect Your AWS Account
              </h4>
              <p>Provide your AWS credentials. StackDrive will auto-provision S3 buckets (Quarantine/Secure) and a KMS Key directly in your account.</p>
              
              <form onSubmit={handleConnect} style={{ width: '100%', marginTop: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label" style={{ fontSize: 'var(--text-xs)' }}>ACCESS KEY ID</label>
                    <input 
                        type="text" 
                        className="form-input" 
                        placeholder="AKIAIOSFODNN7EXAMPLE" 
                        value={awsForm.access_key}
                        onChange={(e) => setAwsForm({...awsForm, access_key: e.target.value})}
                    />
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label" style={{ fontSize: 'var(--text-xs)' }}>SECRET ACCESS KEY</label>
                    <input 
                        type="password" 
                        className="form-input" 
                        placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" 
                        value={awsForm.secret_key}
                        onChange={(e) => setAwsForm({...awsForm, secret_key: e.target.value})}
                    />
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label" style={{ fontSize: 'var(--text-xs)' }}>REGION</label>
                    <select 
                        className="form-input" 
                        value={awsForm.region}
                        onChange={(e) => setAwsForm({...awsForm, region: e.target.value})}
                    >
                        <option value="us-east-1">us-east-1 (N. Virginia)</option>
                        <option value="us-east-2">us-east-2 (Ohio)</option>
                        <option value="us-west-2">us-west-2 (Oregon)</option>
                        <option value="eu-west-1">eu-west-1 (Ireland)</option>
                        <option value="ap-south-1">ap-south-1 (Mumbai)</option>
                    </select>
                </div>
                <button
                    type="submit"
                    className="btn btn-primary"
                    style={{ marginTop: 'var(--space-2)' }}
                    disabled={connecting}
                    id="connect-aws"
                >
                    {connecting ? (
                    <><span className="spinner" /> Provisioning Infrastructure...</>
                    ) : (
                    <><Cloud size={16} /> Provision AWS Account</>
                    )}
                </button>
              </form>
            </div>
          </div>
        )}
      </div>

      {/* User Profile */}
      <div className="settings-section stagger-3">
        <h3 className="settings-section__title">
          <User size={18} />
          User Profile
        </h3>
        <div className="profile-card">
          <div className="profile-card__row">
            <Mail size={16} className="profile-card__icon" />
            <div>
              <span className="profile-card__label">Email</span>
              <span className="profile-card__value">{user?.email || 'user@stackdrive.io'}</span>
            </div>
          </div>
          <div className="profile-card__row">
            <Calendar size={16} className="profile-card__icon" />
            <div>
              <span className="profile-card__label">Account Created</span>
              <span className="profile-card__value">{user?.created_at ? new Date(user.created_at).toLocaleString() : 'N/A'}</span>
            </div>
          </div>
          <div className="profile-card__row">
            <Key size={16} className="profile-card__icon" />
            <div>
              <span className="profile-card__label">User ID</span>
              <span className="profile-card__value mono" style={{ fontSize: 'var(--text-xs)' }}>{user?.id || 'N/A'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Account Actions */}
      <div className="settings-section stagger-4">
        <h3 className="settings-section__title">
          <Shield size={18} />
          Account
        </h3>
        <button className="btn btn-danger" onClick={onLogout} id="logout-btn">
          <LogOut size={14} />
          Log Out
        </button>
      </div>

      {/* Disconnect Modal */}
      <Modal
        isOpen={showDisconnect}
        onClose={() => setShowDisconnect(false)}
        title="Reconnect AWS?"
        actions={
          <>
            <button className="btn btn-secondary" onClick={() => setShowDisconnect(false)}>Cancel</button>
            <button className="btn btn-danger" onClick={handleDisconnect}>Yes, Disconnect</button>
          </>
        }
      >
        <p>This will revoke your current AWS credentials and disconnect your S3 buckets. You'll need to reconnect with a new or same AWS account.</p>
        <p style={{ marginTop: 'var(--space-3)', color: 'var(--color-queue)' }}>
          ⚠ Existing files in your secure bucket will remain accessible through AWS directly.
        </p>
      </Modal>
    </div>
  );
}
