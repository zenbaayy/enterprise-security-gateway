const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);
const mongoose = require('mongoose');
const config = require('./src/config');
const app = require('./src/app');
const { seedUsers } = require('./src/seed');

async function start() {
  await mongoose.connect(config.mongoUri);
  console.log('MongoDB connected');
  if (config.seedUsers) await seedUsers();
  app.listen(config.port, () => console.log(`Gateway running on ${config.baseUrl} (port ${config.port})`));
}

start().catch((err) => {
  console.error('Failed to start:', err.message);
  process.exit(1);
});
