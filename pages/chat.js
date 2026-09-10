import { useEffect, useState, useRef, useCallback } from 'react';
import io from 'socket.io-client';
import * as crypto from '../lib/crypto';
import { useRouter } from 'next/router';

let socket;

const fmtTime = (ts) => {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch { return ''; }
};

const short = (s, n = 44) => (s && s.length > n ? s.slice(0, n) + '…' : s || '');
const byteLen = (b64) => { try { return window.atob(b64).length; } catch { return 0; } };

export default function ChatPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [recipient, setRecipient] = useState('');
  const [text, setText] = useState('');
  const [messages, setMessages] = useState([]);
  const [onlineMap, setOnlineMap] = useState({});
  const [isReady, setIsReady] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState('');
  const [openInspect, setOpenInspect] = useState(null);
  const [keyDraft, setKeyDraft] = useState('');
  const [conversations, setConversations] = useState([]);
  const chatRef = useRef(null);

  // Refs mirror live values so the socket handlers (registered once) never read
  // stale state from their closure.
  const secretKeyRef = useRef('');
  const recipientRef = useRef('');
  const myPublicKeyRef = useRef(null);
  useEffect(() => { secretKeyRef.current = secretKey; }, [secretKey]);
  useEffect(() => { recipientRef.current = recipient; }, [recipient]);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages]);

  useEffect(() => {
    setMounted(true);
    crypto.loadOQS().then(() => setIsReady(true)).catch(console.error);
  }, []);

  const getMyPublicKey = async (me) => {
    if (myPublicKeyRef.current) return myPublicKeyRef.current;
    const res = await fetch(`/api/user/${encodeURIComponent(me)}`);
    if (!res.ok) throw new Error('Could not load your own public key');
    const { publicKey } = await res.json();
    myPublicKeyRef.current = publicKey;
    return publicKey;
  };

  const decryptBlob = async (blob, sk) => {
    const shared = await crypto.decapsulateSecret(blob.kemCipherText, sk);
    return crypto.decryptMessage(blob.cipherText, blob.nonce, shared);
  };

  useEffect(() => {
    if (!mounted) return;
    let cancelled = false;

    (async () => {
      // Identity comes from the signed session cookie, not from localStorage.
      const res = await fetch('/api/me');
      if (!res.ok) { router.push('/'); return; }
      const { username: u } = await res.json();
      if (cancelled) return;
      setUsername(u);

      socket = io({ path: '/api/socketio' });

      socket.on('connect_error', (err) => {
        if (err?.message === 'unauthorized') router.push('/');
      });

      socket.on('online_users', (map) => setOnlineMap(map || {}));
      socket.on('send_error', ({ error: msg }) => setError(msg));

      socket.on('receive_message', async (data) => {
      // Refresh the thread list first, so a message from someone new shows up
      // there even though it is not the conversation on screen.
      loadConversations();

      // Only append to the thread on screen; anything else is persisted and
      // loads as history when that conversation is opened.
      if (data.sender !== recipientRef.current) return;

      const sk = secretKeyRef.current;
      const base = { sender: data.sender, mine: false, at: data.timestamp, enc: data.encryptedData };

      if (!sk) {
        setMessages(prev => [...prev, { ...base, text: 'Encrypted — key missing', locked: true }]);
        return;
      }
      try {
        const decoded = await decryptBlob(data.encryptedData, sk);
        setMessages(prev => [...prev, { ...base, text: decoded }]);
      } catch {
        setMessages(prev => [...prev, { ...base, text: 'Decryption failed', locked: true }]);
      }
      });
    })();

    return () => { cancelled = true; if (socket) socket.disconnect(); };
  }, [mounted]);

  // Load and decrypt the stored conversation whenever the recipient changes.
  useEffect(() => {
    if (!username || !recipient || !secretKey || !isReady) return;

    let cancelled = false;
    const timer = setTimeout(async () => {   // debounced: recipient updates per keystroke
      setLoadingHistory(true);
      try {
        const res = await fetch(
          `/api/messages?user1=${encodeURIComponent(username)}&user2=${encodeURIComponent(recipient)}`
        );
        if (!res.ok) { if (!cancelled) setMessages([]); return; }
        const history = await res.json();

        const out = [];
        for (const m of history) {
          const mine = m.sender === username;
          // Our own messages were sealed to the recipient's key, so we read the
          // copy that was sealed to ours instead.
          const blob = mine ? m.senderCopy : m.encryptedData;
          const base = { sender: m.sender, mine, at: m.timestamp || m.createdAt, enc: blob };

          if (!blob || !blob.kemCipherText) {
            out.push({ ...base, text: 'Encrypted — no readable copy', locked: true });
            continue;
          }
          try {
            out.push({ ...base, text: await decryptBlob(blob, secretKey) });
          } catch {
            out.push({ ...base, text: 'Decryption failed', locked: true });
          }
        }
        if (!cancelled) setMessages(out);
      } catch (e) {
        console.error(e);
      } finally {
        if (!cancelled) setLoadingHistory(false);
      }
    }, 300);

    return () => { cancelled = true; clearTimeout(timer); };
  }, [username, recipient, secretKey, isReady]);

  // The thread list. Previews arrive encrypted and are opened here, so the
  // server never sees them either.
  const loadConversations = useCallback(async () => {
    const sk = secretKeyRef.current;
    if (!sk) return;
    try {
      const res = await fetch('/api/conversations');
      if (!res.ok) return;
      const rows = await res.json();

      const withPreviews = await Promise.all(rows.map(async (c) => {
        let preview = null;
        if (c.lastBlob?.kemCipherText) {
          try { preview = await decryptBlob(c.lastBlob, sk); }
          catch { preview = null; }
        }
        return { ...c, preview };
      }));
      setConversations(withPreviews);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    if (!username || !secretKey || !isReady) return;
    loadConversations();
  }, [username, secretKey, isReady, loadConversations]);

  const handleSend = async (e) => {
    e.preventDefault();
    setError('');
    if (!recipient || !text || !isReady) return;

    const outgoing = text;
    try {
      const res = await fetch(`/api/user/${encodeURIComponent(recipient)}`);
      if (!res.ok) throw new Error(`User "${recipient}" not found`);
      const { publicKey } = await res.json();

      // Sealed for the recipient
      const toThem = await crypto.encapsulateSecret(publicKey);
      const theirs = await crypto.encryptMessage(outgoing, toThem.sharedSecret);

      // Sealed for us, so this message stays readable in our own history
      const toMe = await crypto.encapsulateSecret(await getMyPublicKey(username));
      const mine = await crypto.encryptMessage(outgoing, toMe.sharedSecret);

      const encForThem = { cipherText: theirs.cipherText, nonce: theirs.nonce, kemCipherText: toThem.kemCipherText };

      // No `sender` field: the server takes the identity from our session token.
      socket.emit('send_message', {
        receiver: recipient,
        encryptedData: encForThem,
        senderCopy: { cipherText: mine.cipherText, nonce: mine.nonce, kemCipherText: toMe.kemCipherText }
      });

      setMessages(prev => [...prev, { sender: username, text: outgoing, mine: true, at: Date.now(), enc: encForThem }]);
      setText('');
      loadConversations();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleLogout = async () => {
    try { await fetch('/api/logout', { method: 'POST' }); } catch { /* clear locally anyway */ }
    if (socket) socket.disconnect();
    setSecretKey('');
    secretKeyRef.current = '';
    router.push('/');
  };

  const loadKeyFile = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setKeyDraft(String(reader.result || '').trim());
    reader.readAsText(file);
  };

  if (!mounted) return null;

  /* ---------- unlock screen: paste or upload the secret key ---------- */
  if (!secretKey) {
    return (
      <div className="authWrap">
        <main className="container container--narrow stack">
          <div className="brand">
            <div className="brandMark">🔓</div>
            <div>
              <h1 className="title">Unlock your messages</h1>
              <p className="sub">Signed in as <b>{username || '…'}</b></p>
            </div>
          </div>

          <div className="notice notice--info">
            Paste the contents of <b className="mono">{username}_SECRET.txt</b>, or load the file.
            The key stays in memory only — it is never sent anywhere.
          </div>

          <div className="field">
            <label className="label" htmlFor="sk">ML-KEM-768 secret key</label>
            <textarea
              id="sk"
              className="input mono"
              rows={5}
              placeholder="Paste your secret key…"
              style={{ resize: 'vertical', fontSize: 11, lineHeight: 1.5 }}
              value={keyDraft}
              onChange={e => setKeyDraft(e.target.value)}
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="kf">…or load the key file</label>
            <input id="kf" className="input" type="file" accept=".txt,text/plain"
              onChange={e => loadKeyFile(e.target.files && e.target.files[0])} />
          </div>

          <div className="row">
            <button className="btn btn--ghost" onClick={handleLogout}>Sign out</button>
            <button
              className="btn grow"
              disabled={!keyDraft.trim()}
              onClick={() => { const k = keyDraft.trim(); secretKeyRef.current = k; setSecretKey(k); }}
            >
              Unlock →
            </button>
          </div>
        </main>
      </div>
    );
  }

  /* ---------- chat ---------- */
  const online = !!(recipient && onlineMap[recipient]);

  return (
    <div className="container stack">
      <div className="spread">
        <div className="brand" style={{ marginBottom: 0 }}>
          <div className="brandMark">🔐</div>
          <div>
            <h1 className="title">{username}</h1>
            <p className="sub">Quantum-safe session</p>
          </div>
        </div>

        <div className="row" style={{ flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span className={`badge ${isReady ? 'badge--ok' : 'badge--wait'}`}>
            <span className={`dot ${isReady ? '' : 'dot--pulse'}`} />
            {isReady ? 'Quantum secure' : 'Loading WASM…'}
          </span>
          <button onClick={handleLogout} className="btn btn--ghost btn--sm">Sign out</button>
        </div>
      </div>

      <div className="specGrid">
        <div className="spec">
          <div className="specLabel">Key exchange</div>
          <div className="specValue">ML-KEM-768</div>
        </div>
        <div className="spec">
          <div className="specLabel">Cipher</div>
          <div className="specValue">AES-256-GCM</div>
        </div>
        <div className="spec">
          <div className="specLabel">NIST level</div>
          <div className="specValue">3</div>
        </div>
        <div className="spec">
          <div className="specLabel">Server sees</div>
          <div className="specValue">ciphertext</div>
        </div>
      </div>

      <div className="chatLayout">
        <aside className="convPane">
          <div className="convHead">Conversations</div>

          <div className="convList">
            {conversations.length === 0 && (
              <div className="convEmpty">
                No conversations yet. Type a username on the right to start one.
              </div>
            )}

            {conversations.map((c) => (
              <button
                key={c.username}
                className={`convItem ${c.username === recipient ? 'active' : ''}`}
                onClick={() => setRecipient(c.username)}
              >
                <div className="avatar">
                  {c.username.slice(0, 2).toUpperCase()}
                  <span className={`presence ${onlineMap[c.username] ? 'on' : ''}`} />
                </div>
                <div className="convBody">
                  <div className="convName">
                    <span>{c.username}</span>
                    <span className="convTime">{fmtTime(c.lastAt)}</span>
                  </div>
                  <div className={`convPreview ${c.preview ? '' : 'locked'}`}>
                    {c.preview
                      ? `${c.fromMe ? 'You: ' : ''}${c.preview}`
                      : '🔒 encrypted'}
                  </div>
                </div>
              </button>
            ))}
          </div>

          <hr className="divider" />
          <div className="convHead" style={{ textTransform: 'none', letterSpacing: 0 }}>
            {conversations.length} thread{conversations.length === 1 ? '' : 's'} · previews
            decrypted in your browser
          </div>
        </aside>

      <div className="card stack">
        <div className="row">
          <input
            className="input grow"
            placeholder="Who do you want to message?"
            value={recipient}
            onChange={e => setRecipient(e.target.value)}
          />
          <span className={`badge ${online ? 'badge--ok' : 'badge--muted'}`}>
            <span className="dot" />{online ? 'online' : 'offline'}
          </span>
        </div>

        {error && <div className="notice notice--warn">{error}</div>}

        <div ref={chatRef} className="chatWindow">
          {loadingHistory && (
            <div className="empty"><span className="spinner" style={{ margin: '0 auto' }} /><br />Decrypting history…</div>
          )}

          {!loadingHistory && messages.length === 0 && (
            <div className="empty">
              <span className="big">🛡️</span>
              {recipient
                ? <>No messages with <b>{recipient}</b> yet.<br />Every message is sealed with a fresh ML-KEM encapsulation.</>
                : <>Enter a username above to start a conversation.<br />Messages are encrypted in your browser before they leave.</>}
            </div>
          )}

          {messages.map((m, i) => (
            <div key={i} className={`msgRow ${m.mine ? 'me' : 'them'}`}>
              <div className="msgMeta">
                <span>{m.mine ? 'You' : m.sender}</span>
                {m.at && <span>· {fmtTime(m.at)}</span>}
              </div>

              <div className={`msg ${m.mine ? 'me' : 'them'} ${m.locked ? 'locked' : ''}`}>
                {m.locked && '🔒 '}{m.text}
              </div>

              {m.enc && (
                <button className="inspectBtn" onClick={() => setOpenInspect(openInspect === i ? null : i)}>
                  {openInspect === i ? '▾ hide ciphertext' : '▸ inspect ciphertext'}
                </button>
              )}

              {openInspect === i && m.enc && (
                <div className="inspect">
                  <div><b>KEM ciphertext</b> ({byteLen(m.enc.kemCipherText)} B) — the encapsulated key</div>
                  <div className="cipher">{short(m.enc.kemCipherText, 64)}</div>
                  <div style={{ marginTop: 7 }}><b>AES-GCM nonce</b> ({byteLen(m.enc.nonce)} B)</div>
                  <div className="cipher">{m.enc.nonce}</div>
                  <div style={{ marginTop: 7 }}><b>Payload</b> ({byteLen(m.enc.cipherText)} B) — what the server stored</div>
                  <div className="cipher">{short(m.enc.cipherText, 64)}</div>
                </div>
              )}
            </div>
          ))}
        </div>

        <form onSubmit={handleSend} className="composer">
          <input
            className="input grow"
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder={recipient ? `Message ${recipient}…` : 'Pick a recipient first…'}
            disabled={!recipient}
          />
          <button className="btn" disabled={!isReady || !text.trim() || !recipient}>Send</button>
        </form>
      </div>
      </div>

      <p className="hint" style={{ textAlign: 'center' }}>
        Encryption happens in your browser. The server relays and stores ciphertext only.
      </p>
    </div>
  );
}
