const bcrypt = require('bcryptjs');
const config = require('./config');
const User = require('./models/User');

const ACCOUNTS = [
  { name: 'Super Admin', email: 'superadmin@example.com', password: 'SuperAdmin@123', role: 'SuperAdmin' },
  { name: 'Demo Manager', email: 'manager@example.com', password: 'Manager@1234', role: 'Manager' },
  { name: 'Demo Employee', email: 'employee@example.com', password: 'Employee@123', role: 'Employee' },
];

async function seedUsers() {
  for (const a of ACCOUNTS) {
    const exists = await User.findOne({ email: a.email });
    if (exists) continue;
    const passwordHash = await bcrypt.hash(a.password, config.bcryptRounds);
    await User.create({ name: a.name, email: a.email, passwordHash, role: a.role });
    console.log(`Seeded ${a.role}: ${a.email}`);
  }
}

module.exports = { seedUsers };

// `npm run seed`
if (require.main === module) {
  const mongoose = require('mongoose');
  mongoose
    .connect(config.mongoUri)
    .then(seedUsers)
    .then(() => mongoose.disconnect())
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
