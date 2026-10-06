const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');

// Verifies the Bearer access token and loads the user fresh from the DB.
async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }
    let payload;
    try {
      payload = jwt.verify(token, config.accessSecret);
    } catch (err) {
      const msg = err.name === 'TokenExpiredError' ? 'Access token expired' : 'Invalid access token';
      return res.status(401).json({ error: msg });
    }
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

// RBAC: checkRole(['SuperAdmin']) -> 403 for any other role
const checkRole = (allowedRoles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (!allowedRoles.includes(req.user.role)) {
    return res.status(403).json({
      error: 'Forbidden: insufficient role',
      yourRole: req.user.role,
      requiredRoles: allowedRoles,
    });
  }
  next();
};

module.exports = { authenticate, checkRole };
