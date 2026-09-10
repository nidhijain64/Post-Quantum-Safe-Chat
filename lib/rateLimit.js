// In-memory sliding-window rate limiter.
//
// Scope: one Node process. That is enough for this project, but a multi-instance
// deployment would need a shared store (Redis) so the window is global.

const buckets = new Map();

/**
 * Record an attempt and report whether it is allowed.
 * @returns {{allowed: boolean, remaining: number, retryAfterMs: number}}
 */
export const rateLimit = ({ key, limit, windowMs, now = Date.now() }) => {
  const recent = (buckets.get(key) || []).filter((t) => now - t < windowMs);

  if (recent.length >= limit) {
    buckets.set(key, recent);
    const oldest = recent[0];
    return { allowed: false, remaining: 0, retryAfterMs: windowMs - (now - oldest) };
  }

  recent.push(now);
  buckets.set(key, recent);
  return { allowed: true, remaining: limit - recent.length, retryAfterMs: 0 };
};

export const resetRateLimits = () => buckets.clear();

export const clientIp = (req) => {
  const forwarded = req.headers?.['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
};

/**
 * Express-style guard for API routes. Returns true when the request was
 * rejected (and the 429 response has already been sent).
 */
export const enforceRateLimit = (req, res, { name, limit, windowMs }) => {
  const { allowed, retryAfterMs } = rateLimit({
    key: `${name}:${clientIp(req)}`,
    limit,
    windowMs
  });

  if (!allowed) {
    const seconds = Math.ceil(retryAfterMs / 1000);
    res.setHeader('Retry-After', String(seconds));
    res.status(429).json({ error: `Too many attempts. Try again in ${seconds}s.` });
    return true;
  }
  return false;
};
