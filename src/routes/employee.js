const express = require('express');
const { authenticate, checkRole } = require('../middleware/auth');
const { ROLES } = require('../models/User');

const router = express.Router();

// All authenticated roles
router.get('/profile', authenticate, checkRole(ROLES), (req, res) => {
  res.json({ profile: req.user.toPublic(), memberSince: req.user.createdAt });
});

module.exports = router;
