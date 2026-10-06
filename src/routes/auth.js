const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { passport, enabled } = require('../passport');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const { COOKIE_NAME, signAccessToken, issueRefreshToken, clearRefreshCookie } = require('../utils/tokens');

const router = express.Router();

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const PASS_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$/;
const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', config.bcryptRounds);

/* ---------------------------- LOCAL AUTH ---------------------------- */

router.post('/register', registerLimiter, async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.length > 100) {
      return res.status(400).json({ error: 'Valid name is required' });
    }
    if (typeof email !== 'string' || !EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    if (typeof password !== 'string' || !PASS_RE.test(password)) {
      return res.status(400).json({
        error: 'Password must be 8-72 chars with upper, lower, number and special character',
      });
    }
    const normalized = email.toLowerCase().trim();
    if (await User.findOne({ email: normalized })) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    // Salted + hashed with bcrypt. Role is ALWAYS Employee (never taken from the request body).
    const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
    const user = await User.create({ name: name.trim(), email: normalized, passwordHash, role: 'Employee' });
    res.status(201).json({ message: 'Registered successfully', user: user.toPublic() });
  } catch (err) {
    next(err);
  }
});

router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    // typeof checks also stop NoSQL operator objects like {"$gt": ""}
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+passwordHash');

    // Account lockout
    if (user && user.lockUntil && user.lockUntil > Date.now()) {
      const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked due to failed attempts. Try again in ${mins} minute(s).` });
    }
    if (user && user.lockUntil && user.lockUntil <= Date.now()) {
      user.lockUntil = undefined;
      user.failedLoginAttempts = 0;
    }

    // Always run one bcrypt compare so response time doesn't reveal whether the email exists
    const ok = await bcrypt.compare(password, (user && user.passwordHash) || DUMMY_HASH);
    if (!user || !user.passwordHash || !ok) {
      if (user) {
        user.failedLoginAttempts += 1;
        if (user.failedLoginAttempts >= MAX_FAILED) {
          user.lockUntil = new Date(Date.now() + LOCK_MS);
          user.failedLoginAttempts = 0;
        }
        await user.save();
      }
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    await issueRefreshToken(user, res);
    res.json({ accessToken: signAccessToken(user), expiresIn: 900, user: user.toPublic() });
  } catch (err) {
    next(err);
  }
});

/* ---------------------- REFRESH TOKEN ROTATION ---------------------- */

router.post('/refresh', async (req, res, next) => {
  try {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'No refresh token' });

    let payload;
    try {
      payload = jwt.verify(token, config.refreshSecret);
    } catch (err) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Atomically mark the presented token as used. Only one request can win this.
    const used = await RefreshToken.findOneAndUpdate({ jti: payload.jti, revoked: false }, { revoked: true });
    if (!used) {
      // Token was already used/revoked -> possible theft. Kill the whole session family.
      const known = await RefreshToken.findOne({ jti: payload.jti });
      if (known) await RefreshToken.updateMany({ family: known.family }, { revoked: true });
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token reuse detected. Session revoked, please log in again.' });
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'User no longer exists' });
    }

    await issueRefreshToken(user, res, used.family); // brand-new refresh token, same family
    res.json({ accessToken: signAccessToken(user), expiresIn: 900, user: user.toPublic() });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------ LOGOUT ------------------------------ */

router.post('/logout', async (req, res, next) => {
  try {
    const token = req.cookies && req.cookies[COOKIE_NAME];
    if (token) {
      const payload = jwt.decode(token);
      if (payload && payload.jti) {
        const rec = await RefreshToken.findOne({ jti: payload.jti });
        if (rec) await RefreshToken.updateMany({ family: rec.family }, { revoked: true }); // revoke session
      }
    }
    clearRefreshCookie(res);
    res.json({ message: 'Logged out, refresh token revoked' });
  } catch (err) {
    next(err);
  }
});

/* ------------------------- SOCIAL OAUTH 2.0 ------------------------- */

const STATE_COOKIE = 'oauth_state';
const stateCookieOpts = () => ({
  httpOnly: true,
  secure: config.cookieSecure,
  sameSite: 'lax', // must be Lax: the provider redirects back from another site
  path: '/api/v1/auth',
});

function startOAuth(name, scope) {
  return (req, res, next) => {
    if (!enabled.has(name)) return res.status(501).json({ error: `${name} login is not configured on this server` });
    const state = crypto.randomBytes(24).toString('hex'); // CSRF protection for the OAuth flow
    res.cookie(STATE_COOKIE, state, { ...stateCookieOpts(), maxAge: 10 * 60 * 1000 });
    passport.authenticate(name, { scope, session: false, state })(req, res, next);
  };
}

function finishOAuth(name) {
  return [
    (req, res, next) => {
      if (!enabled.has(name)) return res.status(501).json({ error: `${name} login is not configured` });
      const expected = req.cookies && req.cookies[STATE_COOKIE];
      res.clearCookie(STATE_COOKIE, stateCookieOpts());
      if (!expected || req.query.state !== expected) return res.redirect('/?error=invalid_oauth_state');
      next();
    },
    (req, res, next) => passport.authenticate(name, { session: false, failureRedirect: '/?error=oauth_failed' })(req, res, next),
    async (req, res, next) => {
      try {
        await issueRefreshToken(req.user, res); // our own credentials, as an httpOnly cookie
        res.redirect('/?oauth=success'); // frontend then calls /refresh to obtain the access token
      } catch (err) {
        next(err);
      }
    },
  ];
}

router.get('/google', startOAuth('google', ['profile', 'email']));
router.get('/google/callback', ...finishOAuth('google'));
router.get('/github', startOAuth('github', ['user:email']));
router.get('/github/callback', ...finishOAuth('github'));

module.exports = router;
