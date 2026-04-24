import { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';
import LogoIcon from '../components/LogoIcon';
import EncryptionScene from '../components/EncryptionScene';
import './AuthPages.css';

export default function LogoutPage({ onFinishLogout }) {
  const [runAnim, setRunAnim] = useState(false);

  useEffect(() => {
    // 50ms tick allows the DOM to mount the 100vw state first, then triggers the CSS retract transition
    const tick = setTimeout(() => {
      setRunAnim(true);
    }, 50);

    // After 2.5 seconds, the animation is fully locked, so we tear down the session
    const timer = setTimeout(() => {
      if (onFinishLogout) onFinishLogout();
    }, 2500);

    return () => {
      clearTimeout(tick);
      clearTimeout(timer);
    };
  }, [onFinishLogout]);

  return (
    <div className={`auth-split-layout logout-state ${runAnim ? 'run-anim' : ''}`}>
      {/* ── LEFT PANEL: 3D Scene ── */}
      <div className="auth-scene-panel">
        <div className="scene-canvas-wrapper">
          <EncryptionScene variant="logout" isLocking={runAnim} />
        </div>

        {/* Overlay text - fades IN during lock loop */}
        <div className="scene-overlay-text">
          <div className="scene-badge">
            <Shield size={13} />
            <span>Zero-Trust Architecture</span>
          </div>
          <h1 className="scene-headline">
            Session<br />
            <span className="scene-headline-accent">Terminated</span>
          </h1>
          <p className="scene-description">
            Connection successfully closed.<br/>
            Gateway locked.
          </p>
        </div>
        <div className="scene-bottom-fade" />
      </div>

      {/* ── RIGHT PANEL: Form Slide-in ── */}
      <div className="auth-form-panel">
        <div className="auth-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', opacity: 0.6 }}>
          <div className="auth-logo">
            <div className="logo-icon"><LogoIcon /></div>
            <span className="logo-text">StackDrive</span>
          </div>
          <h2 className="auth-title" style={{ marginTop: '2rem' }}>Locking Gateway...</h2>
          <div className="spinner" style={{ width: 30, height: 30, marginTop: '1rem', borderTopColor: 'var(--accent)' }}/>
        </div>
      </div>
    </div>
  );
}
