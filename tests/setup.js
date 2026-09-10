// A deterministic secret for the auth tests. Never the production one.
process.env.JWT_SECRET = 'test-secret-that-is-definitely-long-enough-000000';
process.env.NODE_ENV = 'test';
