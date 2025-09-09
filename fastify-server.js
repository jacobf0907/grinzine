
// fastify-server.js
require('dotenv').config();
const path = require('path');
const Fastify = require('fastify');
const fastifyHelmet = require('@fastify/helmet');
const fastifyCors = require('@fastify/cors');
const fastifyRateLimit = require('@fastify/rate-limit');
const fastifyStatic = require('@fastify/static');
const fastifyCsrf = require('@fastify/csrf');
const fastifyApi = require('./fastify-api');
const fastifyAuth = require('./fastify-auth');

const app = Fastify({ logger: true, trustProxy: true });

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
  'https://grinzine.com',
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
  allowedHeaders: ['Content-Type', 'Authorization'],
});

// General rate limit: 100 requests per 15 minutes per IP
app.register(fastifyRateLimit, {
  max: 100,
  timeWindow: '15 minutes',
  allowList: [],
  keyGenerator: (req) => req.ip,
});

// Stricter rate limit for login and password reset
app.register(fastifyRateLimit, {
  max: 10,
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
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
  }
});

// CSRF token endpoint for frontend
app.get('/csrf-token', async (request, reply) => {
  return { csrfToken: request.csrfToken() };
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
