import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, Lock, Shield, Cpu, ArrowLeft, Mail, Key } from 'lucide-react';
import LogoIcon from '../components/LogoIcon';
import { useToast } from '../components/Toast';
import api from '../services/api';
import EncryptionScene from '../components/EncryptionScene';
import './AuthPages.css';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  
  // Steps: 'email' | 'otp' | 'password'
  const [step, setStep] = useState('email');
  const [resendTimer, setResendTimer] = useState(0);

  // Cinematic Unlock State
  const [isUnlocking, setIsUnlocking] = useState(false);

  const navigate = useNavigate();
  const { addToast } = useToast();

  // Handle resend countdown
  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  const handleSendOtp = async (e) => {
    e.preventDefault();
    if (!email) {
      setErrors({ email: 'Email is required' });
      return;
    } else if (!/\S+@\S+\.\S+/.test(email)) {
      setErrors({ email: 'Enter a valid email address' });
      return;
    }
    setErrors({});
    setLoading(true);
    try {
      await api.sendOtp(email, 'reset');
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

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) {
      setErrors({ otp: 'Please enter the 6-digit code' });
      return;
    }
    setErrors({});
    setLoading(true);
    try {
      await api.verifyOtp(email, otp, 'reset');
      setStep('password');
      addToast('Email verified successfully. Choose a new password.', 'success');
    } catch (err) {
      if (err.status === 400) {
        setErrors({ otp: 'Invalid or expired OTP' });
      } else {
        addToast(err.message || 'Verification failed', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      setResendTimer(30);
      await api.sendOtp(email, 'reset');
      addToast('Verification code resent!', 'success');
    } catch (err) {
      addToast(err.message || 'Failed to resend code', 'error');
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    const errs = {};
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Password must be at least 6 characters';
    if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match';
    
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      return;
    }

    setErrors({});
    setLoading(true);
    try {
      await api.resetPassword(email, password);
      addToast('Password updated successfully!', 'success');
      
      // Play cinematic unlock
      setIsUnlocking(true);
      
      setTimeout(() => {
        navigate('/login');
      }, 2500);
    } catch (err) {
      addToast(err.message || 'Failed to reset password', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      {/* 3D Cinematic Scene */}
      <div className="auth-visual-panel">
        <EncryptionScene isUnlocking={isUnlocking} />
      </div>

      <div className="auth-form-panel">
        <div className="auth-form-container">
          <div className="auth-header">
            <LogoIcon className="auth-logo" />
            <h1 className="auth-title">Secure Your Account</h1>
            <p className="auth-subtitle">
              {step === 'email' && "Enter your email to receive a recovery code"}
              {step === 'otp' && `Enter the 6-digit code sent to ${email}`}
              {step === 'password' && "Create a secure new password for your account"}
            </p>
          </div>

          {step === 'email' && (
            <form onSubmit={handleSendOtp} className="auth-form">
              <div className="form-group">
                <label className="form-label" htmlFor="email">Email Address</label>
                <div className="input-wrapper">
                  <Mail className="input-icon" />
                  <input
                    id="email"
                    type="email"
                    className={`form-input ${errors.email ? 'input-error' : ''}`}
                    placeholder="name@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={loading}
                  />
                </div>
                {errors.email && <span className="error-message">{errors.email}</span>}
              </div>

              <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
                {loading ? <span className="spinner spinner-white" /> : 'Send Recovery Code'}
              </button>

              <div className="auth-footer">
                <Link to="/login" className="back-link">
                  <ArrowLeft className="back-icon" /> Back to Log In
                </Link>
              </div>
            </form>
          )}

          {step === 'otp' && (
            <form onSubmit={handleVerifyOtp} className="auth-form">
              <div className="form-group">
                <label className="form-label" htmlFor="otp">Verification Code</label>
                <div className="input-wrapper">
                  <Key className="input-icon" />
                  <input
                    id="otp"
                    type="text"
                    maxLength={6}
                    className={`form-input otp-input ${errors.otp ? 'input-error' : ''}`}
                    placeholder="000000"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                    disabled={loading}
                  />
                </div>
                {errors.otp && <span className="error-message">{errors.otp}</span>}
              </div>

              <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
                {loading ? <span className="spinner spinner-white" /> : 'Verify Code'}
              </button>

              <div className="otp-resend-container">
                {resendTimer > 0 ? (
                  <span className="otp-timer">Resend code in {resendTimer}s</span>
                ) : (
                  <button type="button" className="btn-resend" onClick={handleResendOtp}>
                    Resend code
                  </button>
                )}
              </div>

              <div className="auth-footer">
                <button
                  type="button"
                  className="back-link btn-link"
                  onClick={() => setStep('email')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer' }}
                >
                  <ArrowLeft className="back-icon" /> Change Email
                </button>
              </div>
            </form>
          )}

          {step === 'password' && (
            <form onSubmit={handleResetPassword} className="auth-form">
              <div className="form-group">
                <label className="form-label" htmlFor="password">New Password</label>
                <div className="input-wrapper">
                  <Lock className="input-icon" />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    className={`form-input ${errors.password ? 'input-error' : ''}`}
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={loading}
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff /> : <Eye />}
                  </button>
                </div>
                {errors.password && <span className="error-message">{errors.password}</span>}
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="confirmPassword">Confirm Password</label>
                <div className="input-wrapper">
                  <Lock className="input-icon" />
                  <input
                    id="confirmPassword"
                    type={showPassword ? 'text' : 'password'}
                    className={`form-input ${errors.confirmPassword ? 'input-error' : ''}`}
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    disabled={loading}
                  />
                </div>
                {errors.confirmPassword && <span className="error-message">{errors.confirmPassword}</span>}
              </div>

              <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
                {loading ? <span className="spinner spinner-white" /> : 'Reset Password'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
