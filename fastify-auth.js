
// fastify-auth.js
const fp = require('fastify-plugin');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const prisma = require('./db');

// DEBUG: Log env vars at plugin load
console.log('[fastify-auth.js] ENV at module load:', {
  GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
  GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
  JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
  ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
  NODE_ENV: process.env.NODE_ENV
});

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const crypto = require('crypto');

/**
 * Helper: set JWT cookie on reply
 * @param {FastifyReply} reply
 * @param {string|number} userId
 */
function setTokenCookie(reply, userId) {
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
  reply.setCookie('token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: true, // Always secure in production
    path: '/',
    maxAge: 7 * 24 * 60 * 60,
  });
}

/**
 * Fastify Auth Plugin
 * @param {import('fastify').FastifyInstance} fastify
 * @param {*} opts
 */
async function authPlugin(fastify, opts) {
  // DEBUG: Log env vars at plugin registration
  fastify.log.info('[fastify-auth.js] ENV at plugin registration:', {
    GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
    GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
    JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
    ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
    NODE_ENV: process.env.NODE_ENV
  });
  const nodemailer = require('nodemailer');

  /**
   * Request password reset
   * @route POST /auth/request-reset
   */
  fastify.post('/auth/request-reset', async (request, reply) => {
    fastify.log.info('[fastify-auth.js] /auth/request-reset handler ENV:', {
      GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
      GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
      JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    });
    try {
      const { email } = request.body;
      const user = await prisma.user.findUnique({ where: { email } });
      // Always respond the same to prevent user enumeration
      if (!user) {
        return reply.send({ message: 'If your email is registered, a reset link has been sent.' });
      }
      // Generate and hash token
      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const expiry = new Date(Date.now() + 1000 * 60 * 60); // 1 hour
      await prisma.user.update({
        where: { email },
        data: { resetToken: tokenHash, resetTokenExpiry: expiry }
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
        html: `<p>You requested a password reset for GRIN.<br>Click <a href="${resetUrl}">here</a> to reset your password.<br>This link will expire in 1 hour.</p>`
      });
      reply.send({ message: 'If your email is registered, a reset link has been sent.' });
    } catch (err) {
      fastify.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  /**
   * Reset password
   * @route POST /auth/reset-password
   */
  fastify.post('/auth/reset-password', async (request, reply) => {
    fastify.log.info('[fastify-auth.js] /auth/reset-password handler ENV:', {
      GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
      GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
      JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    });
    try {
      const { token, password } = request.body;
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const user = await prisma.user.findFirst({
        where: {
          resetToken: tokenHash,
          resetTokenExpiry: { gte: new Date() }
        }
      });
      if (!user) {
        return reply.status(400).send({ error: 'Invalid or expired token.' });
      }
      const hashed = await bcrypt.hash(password, 10);
      await prisma.user.update({
        where: { id: user.id },
        data: { password: hashed, resetToken: null, resetTokenExpiry: null }
      });
      reply.send({ message: 'Password has been reset.' });
    } catch (err) {
      fastify.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  // Auth preHandler
  fastify.decorate('requireAuth', async function (request, reply) {
    const token = request.cookies.token;
    fastify.log.info('[requireAuth] cookies:', request.cookies);
    fastify.log.info('[requireAuth] token:', token);
    if (!token) {
      fastify.log.error('[requireAuth] No token found in cookies');
      return reply.status(401).send({ error: 'Not authenticated' });
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      fastify.log.info('[requireAuth] decoded JWT:', decoded);
      request.userId = decoded.userId;
      fastify.log.info('[requireAuth] set request.userId:', request.userId);
    } catch (err) {
      fastify.log.error('[requireAuth] Invalid token:', err);
      return reply.status(401).send({ error: 'Invalid token' });
    }
  });

  /**
   * Signup
   * @route POST /auth/signup
   */
  fastify.post('/auth/signup', async (request, reply) => {
    fastify.log.info('[fastify-auth.js] /auth/signup handler ENV:', {
      GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
      GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
      JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    });
    try {
      const { email, password } = request.body;
      const hashed = await bcrypt.hash(password, 10);
      const user = await prisma.user.create({ data: { email, password: hashed } });
      reply.send({ message: 'User created', userId: user.id });
    } catch (err) {
      fastify.log.error(err);
      reply.status(400).send({ error: 'User already exists or invalid data' });
    }
  });

  /**
   * Login
   * @route POST /auth/login
   */
  fastify.post('/auth/login', async (request, reply) => {
    fastify.log.info('[fastify-auth.js] /auth/login handler ENV:', {
      GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
      GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
      JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    });
    try {
      const { email, password } = request.body;
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) return reply.status(401).send({ error: 'Invalid email or password' });
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return reply.status(401).send({ error: 'Invalid email or password' });
      setTokenCookie(reply, user.id);
      reply.send({ message: 'Login successful' });
    } catch (err) {
      fastify.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  /**
   * My Library (protected)
   * @route GET /auth/my-library
   */
  fastify.get('/auth/my-library', { preHandler: fastify.requireAuth }, async (request, reply) => {
    fastify.log.info('[fastify-auth.js] /auth/my-library handler ENV:', {
      GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
      GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
      JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    });
    try {
      const purchases = await prisma.purchase.findMany({
        where: { userId: request.userId },
        include: { issue: true }
      });
      const user = await prisma.user.findUnique({ where: { id: request.userId } });
      reply.send({ purchases, email: user ? user.email : null });
    } catch (err) {
      fastify.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  /**
   * Logout
   * @route POST /auth/logout
   */
  fastify.post('/auth/logout', { preHandler: fastify.requireAuth }, async (request, reply) => {
    fastify.log.info('[fastify-auth.js] /auth/logout handler ENV:', {
      GMAIL_USER: process.env.GMAIL_USER ? '[set]' : '[not set]',
      GMAIL_PASS: process.env.GMAIL_PASS ? '[set]' : '[not set]',
      JWT_SECRET: process.env.JWT_SECRET ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    });
    try {
      reply.clearCookie('token', { path: '/' });
      reply.send({ message: 'Logged out' });
    } catch (err) {
      fastify.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });
}

module.exports = fp(authPlugin);
