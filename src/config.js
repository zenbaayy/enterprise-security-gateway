require('dotenv').config();

for (const key of ['MONGODB_URI', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET']) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const port = Number(process.env.PORT) || 5000;
const baseUrl = (process.env.BASE_URL || `http://localhost:${port}`).replace(/\/$/, '');

module.exports = {
  port,
  baseUrl,
  isProd: process.env.NODE_ENV === 'production',
  mongoUri: process.env.MONGODB_URI,
  accessSecret: process.env.JWT_ACCESS_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  accessTtl: '15m',
  refreshTtlMs: 7 * 24 * 60 * 60 * 1000,
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 12,
  cookieSecure: process.env.COOKIE_SECURE !== 'false',
  allowedOrigins: [baseUrl, ...(process.env.CLIENT_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean)],
  seedUsers: process.env.SEED_TEST_USERS !== 'false',
  google: { clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET },
  github: { clientID: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET },
};
