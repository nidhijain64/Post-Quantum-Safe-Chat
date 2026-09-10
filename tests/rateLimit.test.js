import { describe, it, expect, beforeEach } from 'vitest';
import { rateLimit, resetRateLimits, clientIp, enforceRateLimit } from '../lib/rateLimit';

beforeEach(() => resetRateLimits());

describe('rateLimit', () => {
  const opts = { key: 'login:1.2.3.4', limit: 3, windowMs: 1000 };

  it('allows up to the limit then blocks', () => {
    expect(rateLimit({ ...opts, now: 0 }).allowed).toBe(true);
    expect(rateLimit({ ...opts, now: 0 }).allowed).toBe(true);
    expect(rateLimit({ ...opts, now: 0 }).allowed).toBe(true);
    expect(rateLimit({ ...opts, now: 0 }).allowed).toBe(false);
  });

  it('counts down remaining attempts', () => {
    expect(rateLimit({ ...opts, now: 0 }).remaining).toBe(2);
    expect(rateLimit({ ...opts, now: 0 }).remaining).toBe(1);
    expect(rateLimit({ ...opts, now: 0 }).remaining).toBe(0);
  });

  it('lets the window slide, so old attempts stop counting', () => {
    for (let i = 0; i < 3; i++) rateLimit({ ...opts, now: 0 });
    expect(rateLimit({ ...opts, now: 999 }).allowed).toBe(false);  // still inside the window
    expect(rateLimit({ ...opts, now: 1001 }).allowed).toBe(true);  // first attempt aged out
  });

  it('reports how long to wait', () => {
    for (let i = 0; i < 3; i++) rateLimit({ ...opts, now: 0 });
    expect(rateLimit({ ...opts, now: 400 }).retryAfterMs).toBe(600);
  });

  it('keeps separate buckets per key', () => {
    for (let i = 0; i < 3; i++) rateLimit({ ...opts, now: 0 });
    expect(rateLimit({ ...opts, now: 0 }).allowed).toBe(false);
    expect(rateLimit({ ...opts, key: 'login:9.9.9.9', now: 0 }).allowed).toBe(true);
  });

  it('does not let a blocked caller extend its own window', () => {
    for (let i = 0; i < 3; i++) rateLimit({ ...opts, now: 0 });
    rateLimit({ ...opts, now: 500 });                              // rejected attempt
    expect(rateLimit({ ...opts, now: 1001 }).allowed).toBe(true);  // must not have been recorded
  });
});

describe('clientIp', () => {
  it('prefers the first x-forwarded-for entry', () => {
    expect(clientIp({ headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2' } })).toBe('1.1.1.1');
  });

  it('falls back to the socket address', () => {
    expect(clientIp({ headers: {}, socket: { remoteAddress: '3.3.3.3' } })).toBe('3.3.3.3');
  });

  it('never returns undefined', () => {
    expect(clientIp({ headers: {} })).toBe('unknown');
  });
});

describe('enforceRateLimit', () => {
  const mockRes = () => {
    const res = { statusCode: null, body: null, headers: {} };
    res.status = (c) => { res.statusCode = c; return res; };
    res.json = (b) => { res.body = b; return res; };
    res.setHeader = (k, v) => { res.headers[k] = v; };
    return res;
  };
  const req = { headers: { 'x-forwarded-for': '5.5.5.5' } };

  it('passes requests under the limit', () => {
    const res = mockRes();
    expect(enforceRateLimit(req, res, { name: 'test', limit: 2, windowMs: 60000 })).toBe(false);
    expect(res.statusCode).toBeNull();
  });

  it('sends 429 with Retry-After once exceeded', () => {
    const cfg = { name: 'test', limit: 1, windowMs: 60000 };
    enforceRateLimit(req, mockRes(), cfg);

    const res = mockRes();
    expect(enforceRateLimit(req, res, cfg)).toBe(true);
    expect(res.statusCode).toBe(429);
    expect(res.headers['Retry-After']).toBeDefined();
  });
});
