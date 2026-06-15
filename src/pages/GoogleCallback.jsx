import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '../services/api';

export default function GoogleCallback({ onLogin }) {
  const [params] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const token = params.get('token');
    const userJson = params.get('user');
    if (token && userJson) {
      const user = JSON.parse(decodeURIComponent(userJson));
      api.setToken(token);
      onLogin(user);
      navigate('/overview');
    } else {
      navigate('/login');
    }
  }, [params, onLogin, navigate]);

  return (
    <div style={{ color: 'white', textAlign: 'center', marginTop: '40vh', fontFamily: 'Inter, sans-serif' }}>
      <div className="spinner" style={{ margin: '0 auto 16px auto', width: '32px', height: '32px', borderTopColor: 'var(--accent)' }}></div>
      Completing sign-in...
    </div>
  );
}
