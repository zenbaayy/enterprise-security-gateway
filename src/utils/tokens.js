const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const RefreshToken = require('../models/RefreshToken');

const COOKIE_NAME = 'refreshToken';

const cookieOptions = () => ({
  httpOnly: true,
  secure: config.cookieSecure,
  sameSite: 'strict',
  path: '/api/v1/auth',
});

function signAccessToken(user) {
  return jwt.sign({ role: user.role }, config.accessSecret, {
    subject: String(user._id),
    expiresIn: config.accessTtl,
  });
}

// Creates a refresh token, stores its jti, and sets it as an httpOnly cookie.
async function issueRefreshToken(user, res, family) {
  const jti = crypto.randomUUID();
  const fam = family || crypto.randomUUID();
  const token = jwt.sign({ fam }, config.refreshSecret, {
    subject: String(user._id),
    jwtid: jti,
    expiresIn: Math.floor(config.refreshTtlMs / 1000),
  });
  await RefreshToken.create({
    jti,
    user: user._id,
    family: fam,
    expiresAt: new Date(Date.now() + config.refreshTtlMs),
  });
  res.cookie(COOKIE_NAME, token, { ...cookieOptions(), maxAge: config.refreshTtlMs });
  return fam;
}

function clearRefreshCookie(res) {
  res.clearCookie(COOKIE_NAME, cookieOptions());
}

module.exports = { COOKIE_NAME, signAccessToken, issueRefreshToken, clearRefreshCookie };
