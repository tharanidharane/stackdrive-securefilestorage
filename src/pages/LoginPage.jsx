import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, LogIn, Shield, Lock, Cpu, ArrowLeft } from 'lucide-react';
import LogoIcon from '../components/LogoIcon';
import { useToast } from '../components/Toast';
import api from '../services/api';
import EncryptionScene from '../components/EncryptionScene';
import GoogleIcon from '../components/GoogleIcon';
import './AuthPages.css';

export default function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  
  // Cinematic Unlock State
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [lastLoginInfo, setLastLoginInfo] = useState('');

  // OTP State
  const [step, setStep] = useState('form'); // 'form' | 'otp'
  const [otp, setOtp] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const [resendTimer, setResendTimer] = useState(0);
  
  const navigate = useNavigate();
  const { addToast } = useToast();

  // Handle resend countdown
  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  const validateForm = () => {
    const errs = {};
    if (!email) errs.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(email)) errs.email = 'Enter a valid email';
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Minimum 6 characters';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSendOtp = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;
    setLoading(true);
    try {
      await api.sendOtp(email, 'login');
      setStep('otp');
      setResendTimer(30);
      addToast('Verification code sent to your email', 'success');
    } catch (err) {
      if (err.status === 404) {
        setErrors({ email: 'No account found with this email' });
      } else {
        addToast(err.message || 'Failed to send verification code', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAndLogin = async (e) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) {
      setErrors({ otp: 'Please enter 6-digit code' });
      return;
    }
    setOtpLoading(true);
    try {
      // Step 2: verify OTP
      await api.verifyOtp(email, otp, 'login');
      
      // Step 3: Validate password and perform actual login
      const loginData = await api.login(email, password);
      
      // Format last login info if available
      if (loginData.user && loginData.user.last_login_at) {
        const dateStr = new Date(loginData.user.last_login_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
        setLastLoginInfo(`Last signed in from ${loginData.user.last_login_device || 'Unknown'} at ${dateStr} from ${loginData.user.last_login_ip || 'Unknown'}`);
      } else {
        setLastLoginInfo('First login to StackDrive');
      }

      // Play cinematic unlock
      setIsUnlocking(true);
      
      setTimeout(() => {
        onLogin(loginData.user);
        navigate('/overview');
      }, 2500);

    } catch (err) {
      if (err.status === 400) {
        setErrors({ otp: 'Invalid or expired OTP' });
      } else if (err.status === 401) {
        setErrors({ otp: err.message || 'Authentication failed' });
      } else {
        addToast(err.message || 'Verification failed', 'error');
      }
      setOtpLoading(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      setResendTimer(30);
      await api.sendOtp(email, 'login');
      addToast('Verification code resent!', 'success');
    } catch (err) {
      addToast(err.message || 'Failed to resend code', 'error');
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const { auth_url } = await api.getGoogleAuthUrl();
      window.location.href = auth_url;
    } catch (err) {
      addToast(err.message || 'Failed to initialize Google login', 'error');
    }
  };

  return (
    <div className={`auth-split-layout ${isUnlocking ? 'unlocking' : ''}`}>

      {/* ── LEFT PANEL: 3D Scene ── */}
      <div className={`auth-scene-panel ${isUnlocking ? 'unlocking' : ''}`}>
        <div className="scene-canvas-wrapper">
          <EncryptionScene variant="login" isUnlocking={isUnlocking} />
        </div>

        {/* Overlay text - fades out during unlock */}
        <div className={`scene-overlay-text ${isUnlocking ? 'unlocking' : ''}`}>
          <div className="scene-badge">
            <Shield size={13} />
            <span>Zero-Trust Architecture</span>
          </div>
          <h1 className="scene-headline">
            Quantum-Safe<br />
            <span className="scene-headline-accent">Encryption</span>
          </h1>
          <p className="scene-description">
            ML-KEM / Kyber · ML-DSA / Dilithium<br />
            AES-256 · 4-Layer Defense Pipeline
          </p>
          <div className="scene-stat-row">
            <div className="scene-stat">
              <Cpu size={14} />
              <span>Post-Quantum</span>
            </div>
            <div className="scene-stat">
              <Lock size={14} />
              <span>Zero-Day Sandbox</span>
            </div>
          </div>
        </div>

        <div className="scene-bottom-fade" />
      </div>

      {/* ── RIGHT PANEL: Auth Form ── */}
      <div className={`auth-form-panel ${isUnlocking ? 'unlocking' : ''}`}>
        <div className="auth-card">
          <div className="auth-logo">
            <div className="logo-icon"><LogoIcon /></div>
            <span className="logo-text">StackDrive</span>
          </div>

          {isUnlocking ? (
            <div style={{ textAlign: 'center', padding: '2rem 0' }}>
              <h2 className="auth-title">Unlocking Gateway...</h2>
              <div className="spinner" style={{ width: 30, height: 30, margin: '2rem auto', borderTopColor: 'var(--accent)' }}/>
              {lastLoginInfo && (
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '280px', margin: '0 auto', lineHeight: '1.5' }}>
                  {lastLoginInfo}
                </p>
              )}
            </div>
          ) : step === 'form' ? (
            <>
              <h2 className="auth-title">Welcome Back</h2>
              <p className="auth-subtitle">Sign in to your secure file gateway</p>

              {/* Google OAuth Button */}
              <button 
                type="button" 
                className="btn btn-google" 
                onClick={handleGoogleLogin}
                disabled={isUnlocking}
              >
                <GoogleIcon />
                Sign in with Google
              </button>
              <div className="auth-divider"><span>or</span></div>

              <form onSubmit={handleSendOtp} id="login-form">
                <div className="form-group">
                  <label className="form-label" htmlFor="login-email">Email Address</label>
                  <input
                    id="login-email"
                    type="email"
                    className={`form-input ${errors.email ? 'error' : ''}`}
                    value={email}
                    onChange={e => { setEmail(e.target.value); setErrors(prev => ({ ...prev, email: '' })); }}
                    placeholder="you@company.com"
                    autoComplete="email"
                    disabled={isUnlocking}
                  />
                  {errors.email && <span className="form-error">{errors.email}</span>}
                </div>

                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <label className="form-label" htmlFor="login-password" style={{ margin: 0 }}>Password</label>
                    <Link to="/forgot" style={{ fontSize: '12px', color: 'var(--accent)', textDecoration: 'none' }}>Forgot Password?</Link>
                  </div>
                  <div className="password-wrapper">
                    <input
                      id="login-password"
                      type={showPassword ? 'text' : 'password'}
                      className={`form-input ${errors.password ? 'error' : ''}`}
                      value={password}
                      onChange={e => { setPassword(e.target.value); setErrors(prev => ({ ...prev, password: '' })); }}
                      placeholder="••••••••"
                      autoComplete="current-password"
                      disabled={isUnlocking}
                    />
                    <button
                      type="button"
                      className="password-toggle"
                      onClick={() => setShowPassword(!showPassword)}
                      tabIndex={-1}
                      disabled={isUnlocking}
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  {errors.password && <span className="form-error">{errors.password}</span>}
                </div>

                <button type="submit" className="btn btn-primary" disabled={loading || isUnlocking} id="login-submit">
                  {loading ? <span className="spinner" /> : <LogIn size={16} />}
                  {loading ? 'Sending Code...' : 'Sign In'}
                </button>
              </form>

              <p className="auth-footer">
                Don't have an account? <Link to="/signup">Create Account</Link>
              </p>
            </>
          ) : (
            <>
              <div className="back-link" onClick={() => { setStep('form'); setErrors({}); }}>
                <ArrowLeft size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                Back
              </div>
              <h2 className="auth-title">Verify Your Identity</h2>
              <p className="auth-subtitle">Two-factor authentication required</p>

              <form onSubmit={handleVerifyAndLogin} id="otp-form">
                <div className="form-group">
                  <div className="otp-hint">Enter the 6-digit code sent to {email}</div>
                  <input
                    type="text"
                    className={`form-input otp-input ${errors.otp ? 'error' : ''}`}
                    maxLength={6}
                    autoFocus
                    value={otp}
                    onChange={e => { setOtp(e.target.value.replace(/\D/g, '')); setErrors(prev => ({ ...prev, otp: '' })); }}
                    placeholder="000000"
                    disabled={otpLoading || isUnlocking}
                  />
                  {errors.otp && <span className="form-error" style={{ textAlign: 'center', display: 'block' }}>{errors.otp}</span>}
                </div>

                <button type="submit" className="btn btn-primary" disabled={otpLoading || isUnlocking} id="otp-submit">
                  {otpLoading ? <span className="spinner" /> : <Shield size={16} />}
                  {otpLoading ? 'Unlocking Gateway...' : 'Verify & Sign In'}
                </button>

                <div className="otp-resend">
                  {resendTimer > 0 ? (
                    `Resend code in ${resendTimer}s`
                  ) : (
                    <button type="button" onClick={handleResendOtp} disabled={otpLoading || isUnlocking}>
                      Resend Code
                    </button>
                  )}
                </div>
              </form>
            </>
          )}

        </div>
      </div>
    </div>
  );
}
