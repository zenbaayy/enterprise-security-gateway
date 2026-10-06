const mongoose = require('mongoose');

// Only the token's unique id (jti) is stored - never the token itself.
const refreshTokenSchema = new mongoose.Schema({
  jti: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  family: { type: String, required: true, index: true }, // one family = one login session chain
  revoked: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
});

// MongoDB auto-deletes expired records
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
