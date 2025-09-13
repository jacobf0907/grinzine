console.log('DEPLOY TEST: 2025-09-12 :: unique log for troubleshooting env issue');
// Only load .env in development
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
// Debug logs
console.log('DEBUG: All environment variables at startup:', process.env);
console.log('DEBUG: STRIPE_MODE:', process.env.STRIPE_MODE);
console.log('DEBUG: STRIPE_SECRET_KEY_TEST:', process.env.STRIPE_SECRET_KEY_TEST ? '[set]' : '[not set]');

const path = require('path');
const Fastify = require('fastify');
const fastifyHelmet = require('@fastify/helmet');
const fastifyFormbody = require('@fastify/formbody');
const fastifyCors = require('@fastify/cors');
const fastifyRateLimit = require('@fastify/rate-limit');
const fastifyStatic = require('@fastify/static');
const fastifyCsrf = require('@fastify/csrf');
const fastifyCookie = require('@fastify/cookie');
const fastifyApi = require('./fastify-api');
const fastifyAuth = require('./fastify-auth');
const Stripe = require('stripe');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { ISSUES } = require('./issues');

const app = Fastify({ logger: true, trustProxy: true });

// --- TEMPORARY: Protected test route in main context to debug plugin encapsulation ---
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// Inline requireAuth logic (copied from fastify-auth.js)
async function requireAuthMain(request, reply) {
  const token = request.cookies.token;
  app.log.info('[requireAuthMain] request.raw.headers:', request.raw.headers);
  app.log.info('[requireAuthMain] request.cookies:', request.cookies);
  app.log.info('[requireAuthMain] token:', token);
  if (!token) {
    app.log.error('[requireAuthMain] No token found in cookies');
    return reply.status(401).send({ error: 'Not authenticated' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    app.log.info('[requireAuthMain] decoded JWT:', decoded);
    request.userId = decoded.userId;
    app.log.info('[requireAuthMain] set request.userId:', request.userId);
  } catch (err) {
    app.log.error('[requireAuthMain] Invalid token:', err);
    return reply.status(401).send({ error: 'Invalid token' });
  }
}

// Protected test route
app.get('/protected-test-main', { preHandler: requireAuthMain }, async (request, reply) => {
  app.log.info('[protected-test-main] userId:', request.userId);
  reply.send({ message: 'Authenticated in main context!', userId: request.userId });
});


// Minimal /create-checkout-session route for env var testing (bypasses plugin)
app.post('/create-checkout-session-test', async (request, reply) => {
  app.log.info('[CHECKOUT-TEST] FULL ENV:', process.env);
  app.log.info('[CHECKOUT-TEST] ENV KEYS:', Object.keys(process.env)); // DEBUG: List all env keys
  app.log.info('[CHECKOUT-TEST] STRIPE ENV VARS:', {
    STRIPE_MODE: process.env.STRIPE_MODE,
    STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE,
    STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST,
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY
  });
  app.log.info('[CHECKOUT-TEST] TEST_SECRET:', process.env.TEST_SECRET); // DEBUG: Log TEST_SECRET
  const STRIPE_MODE = process.env.STRIPE_MODE || 'live';
  const STRIPE_SECRET_KEY = STRIPE_MODE === 'live'
    ? process.env.STRIPE_SECRET_KEY_LIVE
    : process.env.STRIPE_SECRET_KEY_TEST;
  const stripe = Stripe(STRIPE_SECRET_KEY);
  app.log.info('[CHECKOUT-TEST] STRIPE_MODE:', STRIPE_MODE);
  app.log.info('[CHECKOUT-TEST] STRIPE_SECRET_KEY:', STRIPE_SECRET_KEY ? '[set]' : '[not set]');
  try {
    const { priceId, userId } = request.body || {};
    if (!userId) {
      app.log.error('[CHECKOUT-TEST] Missing userId in request body');
      return reply.status(400).send({ error: 'Missing userId in request body' });
    }
    const issue = ISSUES.find(i => i.priceIdLive === priceId || i.priceIdTest === priceId);
    if (!issue) {
      app.log.warn('[CHECKOUT-TEST] Invalid or unknown priceId:', priceId);
      return reply.status(400).send({ error: 'Invalid or unknown priceId' });
    }
    const selectedPriceId = STRIPE_MODE === 'live' ? issue.priceIdLive : issue.priceIdTest;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      app.log.warn('[CHECKOUT-TEST] User not found for userId:', userId);
      return reply.status(401).send({ error: 'User not found' });
    }
    app.log.info('[CHECKOUT-TEST] Creating Stripe session with:', {
      email: user.email,
      selectedPriceId
    });
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: user.email,
      line_items: [
        {
          price: selectedPriceId,
          quantity: 1,
        },
      ],
      success_url: `https://www.grinzine.com/payment_success.html`,
      cancel_url: `https://www.grinzine.com/payment_cancel.html`,
    });
    app.log.info('[CHECKOUT-TEST] Stripe session created:', session.id);
    reply.send({ url: session.url });
  } catch (err) {
    app.log.error('[CHECKOUT-TEST] Error creating checkout session: ' + (err && err.message ? err.message : String(err)));
    try {
      app.log.error('[CHECKOUT-TEST] Error object: ' + JSON.stringify(err, Object.getOwnPropertyNames(err)));
    } catch (jsonErr) {
      app.log.error('[CHECKOUT-TEST] Error object could not be stringified');
    }
    app.log.error('[CHECKOUT-TEST] Error stack: ' + (err && err.stack ? err.stack : 'No stack'));
    reply.status(500).send({ error: 'Internal server error', details: err && err.message });
  }
});

// Debug route to return all environment variables
app.get('/env-debug', async (request, reply) => {
    Object.keys(process.env).forEach(key => {
        app.log.info(`[ENV-DEBUG] ${key}: ${process.env[key]}`);
    });
    process.env.TEST_SECRET;
    return process.env;
});


// Register cookie parser for auth (must be first, global and not encapsulated for all plugins)
app.register(fastifyCookie, { global: true, encapsulate: false });

// Register formbody parser for urlencoded forms
app.register(fastifyFormbody);

// Security headers (Helmet equivalent)
app.register(fastifyHelmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://js.stripe.com', 'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net', 'https://js.stripe.com', 'https://use.typekit.net', "'unsafe-inline'"],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://use.typekit.net', 'data:'],
      imgSrc: ["'self'", 'data:', 'https://js.stripe.com', 'https://www.instagram.com'],
      connectSrc: ["'self'", 'https://js.stripe.com', 'https://api.stripe.com'],
      frameSrc: ['https://js.stripe.com', 'https://www.instagram.com'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
});

// CORS
const ALLOWED_ORIGINS = [
  'https://www.grinzine.com',
  'https://api.grinzine.com',
  'http://localhost:4242',
  `http://localhost:${process.env.PORT || 4242}`
];
app.register(fastifyCors, {
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      cb(null, true);
      return;
    }
    cb(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token', 'X-CSRF-Token'],
});

// General rate limit: 100 requests per 15 minutes per IP
app.register(fastifyRateLimit, {
  max: 100,
  timeWindow: '15 minutes',
  allowList: [],
  keyGenerator: (req) => req.ip,
});

// Stricter rate limit for login and password reset (even less strict)
app.register(fastifyRateLimit, {
  max: 50,
  timeWindow: '15 minutes',
  keyGenerator: (req) => req.ip,
  allowList: [],
  addHeaders: {
    'x-ratelimit-limit': true,
    'x-ratelimit-remaining': true,
    'x-ratelimit-reset': true
  },
  ban: 0,
  errorResponseBuilder: function (req, context) {
    return { error: 'Too many attempts, please try again later.' };
  },
  routes: ['/auth/login', '/auth/request-reset', '/auth/reset-password']
});

// CSRF protection
app.register(fastifyCsrf, {
  cookie: {
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure: true,
  }
});

// CSRF token endpoint for frontend
app.get('/csrf-token', async (request, reply) => {
  return { csrfToken: request.csrfToken };
});

// Serve /pdfs with CORS headers (like Express)
app.register(fastifyStatic, {
  root: '/data/pdfs',
  prefix: '/pdfs/',
  decorateReply: false,
  setHeaders: (res, path, stat) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
});

// Serve static files from ./docs (like Express)
app.register(fastifyStatic, {
  root: path.join(__dirname, 'docs'),
  prefix: '/',
});


// Register API and auth plugins
app.register(fastifyApi);
app.register(fastifyAuth);

// Register protected routes after app is defined
registerProtectedRoutes(app);

// Health check route
app.get('/health', async (request, reply) => {
  return { status: 'ok' };
});


// POST /create-checkout-session (protected)
function registerProtectedRoutes(app) {
  app.post('/create-checkout-session', { preHandler: requireAuthMain }, async (request, reply) => {
    app.log.info('[DEBUG] request.raw.headers:', request.raw.headers);
    app.log.info('[CHECKOUT] FULL ENV:', process.env);
    app.log.info('[CHECKOUT] STRIPE ENV VARS:', {
      STRIPE_MODE: process.env.STRIPE_MODE,
      STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE,
      STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST,
      STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY
    });
    const STRIPE_MODE = process.env.STRIPE_MODE || 'live';
    const STRIPE_SECRET_KEY = STRIPE_MODE === 'live'
      ? process.env.STRIPE_SECRET_KEY_LIVE
      : process.env.STRIPE_SECRET_KEY_TEST;
    const stripe = Stripe(STRIPE_SECRET_KEY);
    app.log.info('[CHECKOUT] Incoming request body:', request.body);
    app.log.info('[CHECKOUT] Authenticated userId:', request.userId);
    app.log.info('[CHECKOUT] STRIPE_MODE:', STRIPE_MODE);
    app.log.info('[CHECKOUT] STRIPE_SECRET_KEY:', STRIPE_SECRET_KEY ? '[set]' : '[not set]');

    if (!request.userId) {
      app.log.error('[CHECKOUT] No authenticated userId found');
      return reply.status(401).send({ error: 'Not authenticated' });
    }

    try {
      const { priceId } = request.body;
      const issue = ISSUES.find(i => i.priceIdLive === priceId || i.priceIdTest === priceId);
      if (!issue) {
        app.log.warn('[CHECKOUT] Invalid or unknown priceId:', priceId);
        return reply.status(400).send({ error: 'Invalid or unknown priceId' });
      }
      const selectedPriceId = STRIPE_MODE === 'live' ? issue.priceIdLive : issue.priceIdTest;
      const isLocal = request.headers.origin && request.headers.origin.includes('localhost');
      const baseUrl = isLocal
        ? `http://localhost:${process.env.PORT || 4242}`
        : process.env.ALLOWED_ORIGIN;
      const user = await prisma.user.findUnique({ where: { id: request.userId } });
      if (!user) {
        app.log.warn('[CHECKOUT] User not found for userId:', request.userId);
        return reply.status(401).send({ error: 'User not found' });
      }
      app.log.info('[CHECKOUT] Creating Stripe session with:', {
        email: user.email,
        selectedPriceId,
        baseUrl
      });
      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        customer_email: user.email,
        line_items: [
          {
            price: selectedPriceId,
            quantity: 1,
          },
        ],
        success_url: `${baseUrl}/payment_success.html`,
        cancel_url: `${baseUrl}/payment_cancel.html`,
      });
      app.log.info('[CHECKOUT] Stripe session created:', session.id);
      reply.send({ url: session.url });
    } catch (err) {
      if (!err) {
        app.log.error('Checkout session error: err is undefined or null!');
      }
      app.log.error('[CHECKOUT] STRIPE_MODE:', STRIPE_MODE);
      app.log.error('[CHECKOUT] STRIPE_SECRET_KEY:', STRIPE_SECRET_KEY ? '[set]' : '[not set]');
      app.log.error('[CHECKOUT] Error creating checkout session:', err);
      app.log.error('[CHECKOUT] Error as string:', String(err));
      app.log.error('[CHECKOUT] Error type:', typeof err);
      if (err && err.stack) app.log.error('[CHECKOUT] Stack trace:', err.stack);
      if (err && typeof err === 'object') app.log.error('[CHECKOUT] Error object:', JSON.stringify(err, null, 2));
      try {
        const util = require('util');
        app.log.error('[CHECKOUT] Error (util.inspect):', util.inspect(err, { depth: 5 }));
      } catch (e) {}
      reply.status(500).send({ error: 'Internal server error', details: err && err.message });
    }
  });

  // GET /auth/my-library (protected)
  app.get('/auth/my-library', { preHandler: requireAuthMain }, async (request, reply) => {
    app.log.info('[DEBUG] request.raw.headers:', request.raw.headers);
    try {
      const purchases = await prisma.purchase.findMany({
        where: { userId: request.userId },
        include: { issue: true }
      });
      const user = await prisma.user.findUnique({ where: { id: request.userId } });
      reply.send({ purchases, email: user ? user.email : null });
    } catch (err) {
      app.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  // POST /auth/logout (protected)
  app.post('/auth/logout', { preHandler: requireAuthMain }, async (request, reply) => {
    try {
      reply.clearCookie('token', { path: '/' });
      reply.send({ message: 'Logged out' });
    } catch (err) {
      app.log.error(err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });
}
// --- END: Protected routes moved from plugins to main server 

// Error handler for CORS errors and generic errors
app.setErrorHandler(function (error, request, reply) {
  if (error && error.message && error.message.includes('Not allowed by CORS')) {
    reply.status(403).send({ error: 'CORS error: Origin not allowed' });
    return;
  }
  // Handle rate limit errors
  if (error && (error.message === 'Too many attempts, please try again later.' || error.error === 'Too many attempts, please try again later.')) {
    reply.status(429).send({ error: 'Too many attempts, please try again later.' });
    return;
  }
  // Hide stack trace from client
  app.log.error(error);
  reply.status(500).send({ error: 'Internal server error' });
});

// Catch-all 404 handler (should be after all other routes)
app.setNotFoundHandler(function (request, reply) {
  reply.status(404).send({ error: 'Not found' });
});

// Start server
const PORT = process.env.PORT || 4242;
app.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) {
    app.log.error(err);
    process.exit(1);
  }
  app.log.info(`Fastify server listening on ${address}`);
});
