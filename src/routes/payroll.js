const express = require('express');
const mongoose = require('mongoose');
const { authenticate, checkRole } = require('../middleware/auth');
const User = require('../models/User');
const Payroll = require('../models/Payroll');

const router = express.Router();

// Manager + SuperAdmin only
router.post('/approve', authenticate, checkRole(['Manager', 'SuperAdmin']), async (req, res, next) => {
  try {
    const { employeeId, amount, period } = req.body || {};
    if (typeof employeeId !== 'string' || !mongoose.isValidObjectId(employeeId)) {
      return res.status(400).json({ error: 'Valid employeeId is required' });
    }
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }
    if (typeof period !== 'string' || !period.trim() || period.length > 50) {
      return res.status(400).json({ error: 'period is required (e.g. "2026-10")' });
    }
    const employee = await User.findById(employeeId);
    if (!employee) return res.status(404).json({ error: 'Employee not found' });

    const record = await Payroll.create({ employee: employee._id, amount, period: period.trim(), approvedBy: req.user._id });
    res.status(201).json({ message: 'Payroll approved', payroll: record });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
