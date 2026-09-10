// Session handling: a signed JWT carried in an HttpOnly cookie.
//
// The cookie is HttpOnly so page scripts cannot read it, and SameSite=Strict so
// it is not attached to cross-site requests. Every authenticated API route and
// every Socket.io connection derives the username from this token rather than
// trusting anything the client sends in the body.

import jwt from 'jsonwebtoken';

export const COOKIE_NAME = 'pqchat_session';

// Minimal cookie handling. Deliberately dependency-free: the `cookie` package
// renamed its exports between majors, and this is all we need.
export const parseCookieHeader = (header) => {
  const out = {};
  if (!header || typeof header !== 'string') return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[key] = part.slice(eq + 1).trim();
    }
  }
  return out;
};

const serializeCookie = (name, value, { maxAge, secure }) => {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict'
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
};
export const MAX_AGE_SECONDS = 60 * 60 * 8; // 8 hours

const getSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set to at least 32 characters in .env.local');
  }
  return secret;
};

export const signToken = (username) =>
  jwt.sign({ sub: username }, getSecret(), {
    algorithm: 'HS256',
    expiresIn: MAX_AGE_SECONDS
  });

/** @returns the decoded payload, or null if missing/expired/tampered. */
export const verifyToken = (token) => {
  if (!token || typeof token !== 'string') return null;
  try {
    return jwt.verify(token, getSecret(), { algorithms: ['HS256'] });
  } catch {
    return null;
  }
};

const isProd = () => process.env.NODE_ENV === 'production';

export const sessionCookie = (token) =>
  serializeCookie(COOKIE_NAME, token, { maxAge: MAX_AGE_SECONDS, secure: isProd() });

export const clearedCookie = () =>
  serializeCookie(COOKIE_NAME, '', { maxAge: 0, secure: isProd() });

/** Pull the authenticated username straight out of a raw Cookie header. */
export const usernameFromCookieHeader = (header) => {
  const token = parseCookieHeader(header)[COOKIE_NAME];
  const payload = verifyToken(token);
  return payload?.sub ?? null;
};

/**
 * Guard for API routes. Returns the username, or null after sending a 401.
 */
export const requireAuth = (req, res) => {
  const username = usernameFromCookieHeader(req.headers.cookie);
  if (!username) {
    res.status(401).json({ error: 'Not authenticated' });
    return null;
  }
  return username;
};
