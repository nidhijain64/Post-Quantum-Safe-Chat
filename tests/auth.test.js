import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import {
  signToken, verifyToken, sessionCookie, clearedCookie,
  usernameFromCookieHeader, requireAuth, COOKIE_NAME
} from '../lib/auth';

const mockRes = () => {
  const res = { statusCode: null, body: null };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; return res; };
  return res;
};

describe('session tokens', () => {
  it('round-trips a username', () => {
    expect(verifyToken(signToken('alice')).sub).toBe('alice');
  });

  it('rejects a tampered token', () => {
    const token = signToken('alice');
    const forged = token.slice(0, -3) + 'xyz';
    expect(verifyToken(forged)).toBeNull();
  });

  it('rejects a token signed with a different secret', () => {
    const foreign = jwt.sign({ sub: 'mallory' }, 'some-other-secret-of-sufficient-length', {
      algorithm: 'HS256'
    });
    expect(verifyToken(foreign)).toBeNull();
  });

  it('rejects an expired token', () => {
    const expired = jwt.sign({ sub: 'alice' }, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: -10
    });
    expect(verifyToken(expired)).toBeNull();
  });

  it('rejects the "none" algorithm — no algorithm confusion', () => {
    const unsigned = jwt.sign({ sub: 'mallory' }, '', { algorithm: 'none' });
    expect(verifyToken(unsigned)).toBeNull();
  });

  it('rejects empty or malformed input', () => {
    for (const bad of [null, undefined, '', 'not-a-jwt', 42, {}]) {
      expect(verifyToken(bad)).toBeNull();
    }
  });
});

describe('session cookie', () => {
  it('is HttpOnly, SameSite=Strict and path-scoped', () => {
    const cookie = sessionCookie(signToken('alice'));
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Strict');
    expect(cookie).toContain('Path=/');
  });

  it('expires immediately when cleared', () => {
    expect(clearedCookie()).toContain('Max-Age=0');
  });

  it('reads the username back out of a Cookie header', () => {
    const header = `${COOKIE_NAME}=${signToken('bob')}`;
    expect(usernameFromCookieHeader(header)).toBe('bob');
  });

  it('ignores unrelated cookies', () => {
    const header = `theme=dark; ${COOKIE_NAME}=${signToken('bob')}; lang=en`;
    expect(usernameFromCookieHeader(header)).toBe('bob');
  });

  it('returns null when the cookie is absent or junk', () => {
    expect(usernameFromCookieHeader('theme=dark')).toBeNull();
    expect(usernameFromCookieHeader(`${COOKIE_NAME}=garbage`)).toBeNull();
    expect(usernameFromCookieHeader(undefined)).toBeNull();
  });
});

describe('requireAuth', () => {
  it('returns the username for a valid session', () => {
    const req = { headers: { cookie: `${COOKIE_NAME}=${signToken('alice')}` } };
    expect(requireAuth(req, mockRes())).toBe('alice');
  });

  it('sends 401 and returns null without a session', () => {
    const res = mockRes();
    expect(requireAuth({ headers: {} }, res)).toBeNull();
    expect(res.statusCode).toBe(401);
  });
});
