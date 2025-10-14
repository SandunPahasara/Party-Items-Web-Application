// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const router = express.Router();

// Register
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword)
      return res.status(400).json({ msg: "All fields are required." });

    if (password !== confirmPassword)
      return res.status(400).json({ msg: "Passwords do not match." });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ msg: "Email already registered." });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    req.session.userId = newUser._id;
    res.status(201).json({ msg: "User registered successfully." });
  } catch (err) {
    res.status(500).json({ msg: "Server error." });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials." });

    req.session.userId = user._id;
    res.json({ msg: "Login successful." });
  } catch (err) {
    console.error('signup error:',err);
    res.status(500).json({ msg: "Server error." });
  }
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ msg: "Logged out." });
  });
});

module.exports = router;
