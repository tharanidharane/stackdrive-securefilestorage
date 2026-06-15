import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, UserPlus, CheckCircle, ShieldCheck, Zap, Globe, ArrowLeft, Shield } from 'lucide-react';
import LogoIcon from '../components/LogoIcon';
import { useToast } from '../components/Toast';
import api from '../services/api';
import EncryptionScene from '../components/EncryptionScene';
import GoogleIcon from '../components/GoogleIcon';
import './AuthPages.css';

export default function SignupPage({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [verified, setVerified] = useState(false);
  const [createdUser, setCreatedUser] = useState(null);

  // OTP and Step State
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
    if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSendOtp = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;
    setLoading(true);
    try {
      await api.sendOtp(email, 'signup');
      setStep('otp');
      setResendTimer(30);
      addToast('Verification code sent to your email', 'success');
    } catch (err) {
      if (err.status === 409) {
        setErrors({ email: 'An account with this email already exists' });
      } else {
        addToast(err.message || 'Failed to send verification code', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtpAndSignup = async (e) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) {
      setErrors({ otp: 'Please enter 6-digit code' });
      return;
    }
    setOtpLoading(true);
    try {
      // Step 2: verify OTP
      await api.verifyOtp(email, otp, 'signup');

      // Step 3: create account
      const data = await api.signup(email, password, true);
      setCreatedUser(data.user);
      setVerified(true);
    } catch (err) {
      if (err.status === 400) {
        setErrors({ otp: 'Invalid or expired OTP' });
      } else {
        addToast(err.message || 'Signup failed', 'error');
      }
    } finally {
      setOtpLoading(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      setResendTimer(30);
      await api.sendOtp(email, 'signup');
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
      addToast(err.message || 'Failed to initialize Google signup', 'error');
    }
  };

  const handleVerify = () => {
    onLogin(createdUser);
    addToast('Account created successfully! Connect your AWS account to start.', 'success');
    navigate('/settings');
  };

  if (verified) {
    return (
      <div className="auth-split-layout">
        <div className="auth-scene-panel">
          <div className="scene-canvas-wrapper">
            <EncryptionScene variant="verified" />
          </div>
          <div className="scene-bottom-fade" />
        </div>

        <div className="auth-form-panel">
          <div className="auth-card" style={{ textAlign: 'center' }}>
            <div className="verify-icon">
              <CheckCircle size={48} />
            </div>
            <h2 className="auth-title">Email Verified!</h2>
            <p className="auth-subtitle" style={{ marginBottom: 'var(--space-6)' }}>
              Your account has been created and verified. Click below to continue to your dashboard.
            </p>
            <button className="btn btn-primary" onClick={handleVerify} id="verify-continue">
              Continue to Dashboard
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-split-layout">

      {/* ── LEFT PANEL: 3D Scene ── */}
      <div className="auth-scene-panel">
        <div className="scene-canvas-wrapper">
          <EncryptionScene variant="signup" />
        </div>

        <div className="scene-overlay-text">
          <div className="scene-badge">
            <ShieldCheck size={13} />
            <span>Enterprise-Grade Security</span>
          </div>
          <h1 className="scene-headline">
            Secure Every<br />
            <span className="scene-headline-accent">File Upload</span>
          </h1>
          <p className="scene-description">
            Hash Validation · Archive Bomb Defense<br />
            ClamAV · Isolated Docker Sandbox
          </p>
          <div className="scene-stat-row">
            <div className="scene-stat">
              <Zap size={14} />
              <span>Real-Time Alerts</span>
            </div>
            <div className="scene-stat">
              <Globe size={14} />
              <span>AWS KMS + S3</span>
            </div>
          </div>
        </div>

        <div className="scene-bottom-fade" />
      </div>

      {/* ── RIGHT PANEL: Auth Form ── */}
      <div className="auth-form-panel">
        <div className="auth-card">
          <div className="auth-logo">
            <div className="logo-icon"><LogoIcon /></div>
            <span className="logo-text">StackDrive</span>
          </div>

          {step === 'form' ? (
            <>
              <h2 className="auth-title">Create Account</h2>
              <p className="auth-subtitle">Start securing your file uploads today</p>

              {/* Google OAuth Button */}
              <button type="button" className="btn btn-google" onClick={handleGoogleLogin}>
                <GoogleIcon />
                Sign up with Google
              </button>
              <div className="auth-divider"><span>or</span></div>

              <form onSubmit={handleSendOtp} id="signup-form">
                <div className="form-group">
                  <label className="form-label" htmlFor="signup-email">Email Address</label>
                  <input
                    id="signup-email"
                    type="email"
                    className={`form-input ${errors.email ? 'error' : ''}`}
                    value={email}
                    onChange={e => { setEmail(e.target.value); setErrors(prev => ({ ...prev, email: '' })); }}
                    placeholder="you@company.com"
                    autoComplete="email"
                  />
                  {errors.email && <span className="form-error">{errors.email}</span>}
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="signup-password">Password</label>
                  <div className="password-wrapper">
                    <input
                      id="signup-password"
                      type={showPassword ? 'text' : 'password'}
                      className={`form-input ${errors.password ? 'error' : ''}`}
                      value={password}
                      onChange={e => { setPassword(e.target.value); setErrors(prev => ({ ...prev, password: '' })); }}
                      placeholder="Min 6 characters"
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      className="password-toggle"
                      onClick={() => setShowPassword(!showPassword)}
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  {errors.password && <span className="form-error">{errors.password}</span>}
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="signup-confirm">Confirm Password</label>
                  <input
                    id="signup-confirm"
                    type="password"
                    className={`form-input ${errors.confirmPassword ? 'error' : ''}`}
                    value={confirmPassword}
                    onChange={e => { setConfirmPassword(e.target.value); setErrors(prev => ({ ...prev, confirmPassword: '' })); }}
                    placeholder="••••••••"
                    autoComplete="new-password"
                  />
                  {errors.confirmPassword && <span className="form-error">{errors.confirmPassword}</span>}
                </div>

                <button type="submit" className="btn btn-primary" disabled={loading} id="signup-submit">
                  {loading ? <span className="spinner" /> : <UserPlus size={16} />}
                  {loading ? 'Sending Code...' : 'Create Account'}
                </button>
              </form>

              <p className="auth-footer">
                Already have an account? <Link to="/login">Sign In</Link>
              </p>
            </>
          ) : (
            <>
              <div className="back-link" onClick={() => { setStep('form'); setErrors({}); }}>
                <ArrowLeft size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                Back
              </div>
              <h2 className="auth-title">Verify Your Email</h2>
              <p className="auth-subtitle">Verify your email address to complete registration</p>

              <form onSubmit={handleVerifyOtpAndSignup} id="otp-form">
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
                    disabled={otpLoading}
                  />
                  {errors.otp && <span className="form-error" style={{ textAlign: 'center', display: 'block' }}>{errors.otp}</span>}
                </div>

                <button type="submit" className="btn btn-primary" disabled={otpLoading} id="otp-submit">
                  {otpLoading ? <span className="spinner" /> : <Shield size={16} />}
                  {otpLoading ? 'Creating Account...' : 'Verify Email & Create Account'}
                </button>

                <div className="otp-resend">
                  {resendTimer > 0 ? (
                    `Resend code in ${resendTimer}s`
                  ) : (
                    <button type="button" onClick={handleResendOtp} disabled={otpLoading}>
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
