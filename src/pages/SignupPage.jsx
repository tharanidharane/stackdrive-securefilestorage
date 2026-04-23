import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, UserPlus, CheckCircle } from 'lucide-react';
import LogoIcon from '../components/LogoIcon';
import { useToast } from '../components/Toast';
import api from '../services/api';
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
  const navigate = useNavigate();
  const { addToast } = useToast();

  const validate = () => {
    const errs = {};
    if (!email) errs.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(email)) errs.email = 'Enter a valid email';
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Minimum 6 characters';
    if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) return;

    setLoading(true);
    try {
      const data = await api.signup(email, password);
      setCreatedUser(data.user);
      setVerified(true);
    } catch (err) {
      if (err.status === 409) {
        setErrors({ email: err.message });
      } else {
        addToast(err.message || 'Signup failed', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = () => {
    onLogin(createdUser);
    addToast('Account created successfully! Connect your AWS account to start.', 'success');
    navigate('/settings');
  };

  if (verified) {
    return (
      <div className="auth-layout">
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
    );
  }

  return (
    <div className="auth-layout">
      <div className="auth-card">
        <div className="auth-logo">
          <div className="logo-icon"><LogoIcon /></div>
          <span className="logo-text">StackDrive</span>
        </div>

        <h2 className="auth-title">Create Account</h2>
        <p className="auth-subtitle">Start securing your file uploads today</p>

        <form onSubmit={handleSubmit} id="signup-form">
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
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <p className="auth-footer">
          Already have an account? <Link to="/login">Sign In</Link>
        </p>
      </div>
    </div>
  );
}
