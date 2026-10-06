const express = require('express');
const mongoose = require('mongoose');
const { authenticate, checkRole } = require('../middleware/auth');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');

const router = express.Router();

// SuperAdmin only - handy for finding ids to test DELETE
router.get('/', authenticate, checkRole(['SuperAdmin']), async (req, res, next) => {
  try {
    const users = await User.find().sort({ createdAt: 1 });
    res.json({ users: users.map((u) => u.toPublic()) });
  } catch (err) {
    next(err);
  }
});

// SuperAdmin only
router.delete('/:id', authenticate, checkRole(['SuperAdmin']), async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid user id' });
    if (String(req.user._id) === id) return res.status(400).json({ error: 'You cannot delete your own account' });

    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await RefreshToken.deleteMany({ user: id }); // kill their sessions
    res.json({ message: 'User deleted', id });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
