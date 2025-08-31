require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const prisma = require('./db');

const router = express.Router();
router.use(cookieParser());
router.use(express.json());

// Secret for signing JWTs
const JWT_SECRET = process.env.JWT_SECRET || "supersecret"; // use env var in production

// --- Auth Middleware ---
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next(); // ✅ continue to the protected route
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- Protected Route Example ---
router.get("/my-library", requireAuth, async (req, res) => {
  const purchases = await prisma.purchase.findMany({
    where: { userId: req.userId },
    include: { issue: true }
  });
  // Get user email
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  res.json({ purchases, email: user ? user.email : null });
});

// --- SIGNUP ---
router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashed }
    });
    res.json({ message: "User created", userId: user.id });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "User already exists or invalid data" });
  }
});

// --- LOGIN ---
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Invalid email or password" });

  // Create JWT
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });

  // Store in cookie
  res.cookie("token", token, {
    httpOnly: true,
    secure: true, // must be true for cross-site cookies on HTTPS
    sameSite: 'none' // allow cross-origin
  });
  res.json({ message: "Logged in" });
});

const nodemailer = require('nodemailer');
const crypto = require('crypto');
// --- REQUEST PASSWORD RESET ---
router.post('/request-reset', async (req, res) => {
  const { email } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    // Don't reveal if user exists
    return res.json({ message: 'If your email is registered, a reset link has been sent.' });
  }
  // Generate token
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = new Date(Date.now() + 1000 * 60 * 60); // 1 hour
  await prisma.user.update({
    where: { email },
    data: { resetToken: token, resetTokenExpiry: expiry }
  });
  // Send email
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS
    }
  });
  const resetUrl = `${process.env.ALLOWED_ORIGIN || 'https://grinzine.fly.dev'}/reset-password.html?token=${token}`;
  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'GRIN Password Reset',
    html: `<p>You requested a password reset for GRIN.<br>
      Click <a href="${resetUrl}">here</a> to reset your password.<br>
      This link will expire in 1 hour.</p>`
  });
  res.json({ message: 'If your email is registered, a reset link has been sent.' });
});

// --- RESET PASSWORD ---
router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  const user = await prisma.user.findFirst({
    where: {
      resetToken: token,
      resetTokenExpiry: { gte: new Date() }
    }
  });
  if (!user) {
    return res.status(400).json({ error: 'Invalid or expired token.' });
  }
  const hashed = await bcrypt.hash(password, 10);
  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashed, resetToken: null, resetTokenExpiry: null }
  });
  res.json({ message: 'Password has been reset.' });
});

// --- LOGOUT ---
router.post('/logout', (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  });
  res.json({ message: "Logged out" });
});

module.exports = {
  router,
  requireAuth
};