const mongoose = require('mongoose');

const ROLES = ['SuperAdmin', 'Manager', 'Employee'];

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, select: false }, // absent for OAuth-only accounts
    role: { type: String, enum: ROLES, default: 'Employee' },
    googleId: { type: String, unique: true, sparse: true },
    githubId: { type: String, unique: true, sparse: true },
    avatar: String,
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: Date,
  },
  { timestamps: true }
);

userSchema.methods.toPublic = function () {
  return { id: this._id, name: this.name, email: this.email, role: this.role, avatar: this.avatar };
};

module.exports = mongoose.model('User', userSchema);
module.exports.ROLES = ROLES;
