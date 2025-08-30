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

// --- LOGOUT ---
router.post('/logout', (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

module.exports = {
  router,
  requireAuth
};