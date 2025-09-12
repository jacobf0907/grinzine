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

// (Removed duplicate block)


// Debug route to return all environment variables
app.get('/env-debug', async (request, reply) => {
    Object.keys(process.env).forEach(key => {
        app.log.info(`[ENV-DEBUG] ${key}: ${process.env[key]}`);
    });
    process.env.TEST_SECRET;
    return process.env;
});


// Register cookie parser for auth (must be first, global for all plugins)
app.register(fastifyCookie, { global: true });

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

// Health check route
app.get('/health', async (request, reply) => {
  return { status: 'ok' };
});

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
