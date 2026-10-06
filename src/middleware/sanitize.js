const xss = require('xss');
const mongoSanitize = require('express-mongo-sanitize');

// Fields that must never be altered (e.g. passwords may legitimately contain < > &)
const SKIP_KEYS = new Set(['password']);

function clean(value, key) {
  if (SKIP_KEYS.has(key)) return value;
  if (typeof value === 'string') return xss(value).trim();
  if (Array.isArray(value)) return value.map((v) => clean(v));
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) value[k] = clean(value[k], k);
  }
  return value;
}

// 1) strips $ and . operators from keys (NoSQL injection)  2) escapes HTML/JS (XSS)
const noSqlSanitize = mongoSanitize({ replaceWith: '_' });
const xssSanitize = (req, res, next) => {
  if (req.body) req.body = clean(req.body);
  if (req.query) req.query = clean(req.query);
  if (req.params) req.params = clean(req.params);
  next();
};

module.exports = [noSqlSanitize, xssSanitize];
