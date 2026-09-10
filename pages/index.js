import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // Convenience prefill only — the real session lives in an HttpOnly cookie
    // that page scripts cannot read.
    const u = localStorage.getItem('lastUsername');
    if (u) setUsername(u);
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    const u = username.trim();

    if (!u || !password) {
      setError('Please enter both username and password.');
      return;
    }

    setBusy(true);
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password }),
      });
      const data = await res.json();

      if (res.ok) {
        localStorage.setItem('lastUsername', u);
        router.push('/chat');
      } else {
        setError(data.error || 'Invalid username or password');
      }
    } catch (err) {
      setError('Could not reach the server. Is it running?');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="authWrap">
      <main className="container container--narrow stack">
        <div className="brand">
          <div className="brandMark">🔐</div>
          <div>
            <h1 className="title">Quantum-Safe Chat</h1>
            <p className="sub">End-to-end encrypted with ML-KEM-768</p>
          </div>
        </div>

        <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
          <span className="badge">ML-KEM-768</span>
          <span className="badge">AES-256-GCM</span>
          <span className="badge badge--muted">NIST FIPS 203</span>
        </div>

        <hr className="divider" />

        <form onSubmit={handleLogin} className="stack">
          <div className="field">
            <label className="label" htmlFor="u">Username</label>
            <input
              id="u"
              className="input"
              placeholder="your username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="p">Password</label>
            <input
              id="p"
              className="input"
              type="password"
              placeholder="••••••••"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && <div className="notice notice--warn">{error}</div>}

          <button className="btn" type="submit" disabled={busy}>
            {busy ? <span className="row" style={{ justifyContent: 'center' }}><span className="spinner" /> Signing in…</span> : 'Sign in'}
          </button>
        </form>

        <p className="hint" style={{ textAlign: 'center' }}>
          No account yet? <a href="/register">Generate a quantum keypair →</a>
        </p>
      </main>
    </div>
  );
}
