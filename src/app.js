const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const config = require('./config');
const sanitize = require('./middleware/sanitize');
const { apiLimiter } = require('./middleware/rateLimit');
const { passport } = require('./passport');

const app = express();

app.set('trust proxy', 1); // Render/Railway/Vercel sit behind a proxy (needed for correct IP + rate limiting)
app.disable('x-powered-by');

// ---- OWASP: security headers ----
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: config.isProd ? {} : { 'upgrade-insecure-requests': null },
    },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// ---- OWASP: strict CORS (allow-list only) ----
const allowed = new Set(config.allowedOrigins);
app.use(
  cors({
    origin: (origin, cb) => (!origin || allowed.has(origin) ? cb(null, true) : cb(new Error('CORS: origin not allowed'))),
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  })
);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());
app.use(sanitize); // NoSQL-injection + XSS sanitisation of body/query/params
app.use(passport.initialize());

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api', apiLimiter);
app.use('/api/v1/auth', require('./routes/auth'));
app.use('/api/v1/employee', require('./routes/employee'));
app.use('/api/v1/payroll', require('./routes/payroll'));
app.use('/api/v1/users', require('./routes/users'));

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api', (req, res) => res.status(404).json({ error: 'Route not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.message && err.message.startsWith('CORS')) return res.status(403).json({ error: err.message });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON body' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' }); // never leak stack traces
});

module.exports = app;
