import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, LogIn, Shield, Lock, Cpu } from 'lucide-react';
import LogoIcon from '../components/LogoIcon';
import { useToast } from '../components/Toast';
import api from '../services/api';
import EncryptionScene from '../components/EncryptionScene';
import './AuthPages.css';

export default function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  
  // Cinematic Unlock State
  const [isUnlocking, setIsUnlocking] = useState(false);
  
  const navigate = useNavigate();
  const { addToast } = useToast();

  const validate = () => {
    const errs = {};
    if (!email) errs.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(email)) errs.email = 'Enter a valid email';
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Minimum 6 characters';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) return;
    setLoading(true);
    try {
      const data = await api.login(email, password);
      
      // Play cinematic unlock instead of instant navigation
      setIsUnlocking(true);
      
      // Delay global login registration and navigation to let the 2.5s 3D animation breath
      setTimeout(() => {
        onLogin(data.user);
        navigate('/overview');
      }, 2500);

    } catch (err) {
      if (err.status === 401) {
        if (err.message.includes('No account')) {
          setErrors({ email: err.message });
        } else {
          setErrors({ password: err.message });
        }
      } else {
        addToast(err.message || 'Login failed', 'error');
      }
      setLoading(false); // Only stop loading if failed, otherwise let animation play
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

          <h2 className="auth-title">Welcome Back</h2>
          <p className="auth-subtitle">Sign in to your secure file gateway</p>

          <form onSubmit={handleSubmit} id="login-form">
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
              <label className="form-label" htmlFor="login-password">Password</label>
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
              {loading || isUnlocking ? 'Unlocking Gateway...' : 'Sign In'}
            </button>
          </form>

          <p className="auth-footer">
            Don't have an account? <Link to="/signup">Create Account</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
