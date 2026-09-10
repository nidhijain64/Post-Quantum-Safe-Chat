import { useState } from 'react';
import * as crypto from '../lib/crypto';
import { useRouter } from 'next/router';

// Base64 -> raw byte count, so the panel reports true key sizes rather than
// the encoded string length.
const byteLen = (b64) => {
  try { return window.atob(b64).length; } catch { return 0; }
};

export default function Register() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(null); // { pk, sk } once registered

  const downloadKey = (name, sk) => {
    const blob = new Blob([sk], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${name}_SECRET.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const doRegister = async (e) => {
    e.preventDefault();
    setError('');

    const u = username.trim();
    if (!u || !password) return setError('Username and password are required.');
    if (password !== confirm) return setError('Passwords do not match.');

    setLoading(true);
    try {
      // Generates the ML-KEM-768 keypair in-browser; the secret key never leaves this device.
      const keys = await crypto.generateKEMKeyPair();

      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password, publicKey: keys.pk })
      });

      if (res.ok) {
        downloadKey(u, keys.sk);
        setDone({ ...keys, username: u });
      } else {
        const d = await res.json();
        setError(d.error || 'Registration failed');
      }
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (done) {
    return (
      <div className="authWrap">
        <main className="container container--narrow stack">
          <div className="brand">
            <div className="brandMark">✅</div>
            <div>
              <h1 className="title">Keypair generated</h1>
              <p className="sub">Registered as <b>{done.username}</b></p>
            </div>
          </div>

          <div className="notice notice--warn">
            <b>Save {done.username}_SECRET.txt now.</b> It was never sent to the server,
            so nobody — including us — can recover it. Lose it and your messages stay encrypted forever.
          </div>

          <div className="card stack" style={{ gap: 12 }}>
            <div className="spread">
              <span className="label" style={{ margin: 0 }}>Generated key material</span>
              <span className="badge badge--ok"><span className="dot" /> live</span>
            </div>

            <div className="specGrid">
              <div className="spec">
                <div className="specLabel">Algorithm</div>
                <div className="specValue">ML-KEM-768</div>
              </div>
              <div className="spec">
                <div className="specLabel">Public key</div>
                <div className="specValue">{byteLen(done.pk)} B</div>
              </div>
              <div className="spec">
                <div className="specLabel">Secret key</div>
                <div className="specValue">{byteLen(done.sk)} B</div>
              </div>
              <div className="spec">
                <div className="specLabel">NIST level</div>
                <div className="specValue">3</div>
              </div>
            </div>

            <div>
              <div className="label" style={{ marginBottom: 6 }}>Your public key (stored on the server)</div>
              <div className="inspect" style={{ marginTop: 0 }}>
                <span className="cipher">{done.pk.slice(0, 128)}…</span>
              </div>
            </div>
          </div>

          <div className="row">
            <button className="btn btn--ghost grow" onClick={() => downloadKey(done.username, done.sk)}>
              Download key again
            </button>
            <button className="btn grow" onClick={() => router.push('/')}>
              Continue to sign in →
            </button>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="authWrap">
      <main className="container container--narrow stack">
        <div className="brand">
          <div className="brandMark">🔑</div>
          <div>
            <h1 className="title">Create account</h1>
            <p className="sub">A post-quantum keypair is generated in your browser</p>
          </div>
        </div>

        <div className="notice notice--info">
          Your <b>secret key never leaves this device</b>. Only the public key is
          uploaded, so the server can never read your messages.
        </div>

        <form onSubmit={doRegister} className="stack">
          <div className="field">
            <label className="label" htmlFor="u">Username</label>
            <input id="u" className="input" placeholder="pick a username" autoComplete="username"
              value={username} onChange={e => setUsername(e.target.value)} />
          </div>

          <div className="field">
            <label className="label" htmlFor="p">Password</label>
            <input id="p" className="input" type="password" placeholder="••••••••" autoComplete="new-password"
              value={password} onChange={e => setPassword(e.target.value)} />
          </div>

          <div className="field">
            <label className="label" htmlFor="c">Confirm password</label>
            <input id="c" className="input" type="password" placeholder="••••••••" autoComplete="new-password"
              value={confirm} onChange={e => setConfirm(e.target.value)} />
          </div>

          {error && <div className="notice notice--warn">{error}</div>}

          <button className="btn" disabled={loading}>
            {loading
              ? <span className="row" style={{ justifyContent: 'center' }}><span className="spinner" /> Generating ML-KEM-768 keypair…</span>
              : 'Generate keypair & register'}
          </button>
        </form>

        <p className="hint" style={{ textAlign: 'center' }}>
          Already registered? <a href="/">Sign in →</a>
        </p>
      </main>
    </div>
  );
}
