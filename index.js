console.log("Starting server...");
require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');


const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
const app = express();

// CORS setup (must be after app is initialized, before any other middleware/routes)
const ALLOWED_ORIGINS = [
  'https://www.grinzine.com',
  'https://grinzine.com',
  `http://localhost:${process.env.PORT || 4242}`
];
const corsOptions = {
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// General rate limit: 100 requests per 15 minutes per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

// Stricter rate limit for login and password reset
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Only 10 attempts per 15 minutes
  message: 'Too many attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to login and password reset routes
app.use('/auth/login', authLimiter);
app.use('/auth/request-reset', authLimiter);
app.use('/auth/reset-password', authLimiter);
// Enforce HTTPS for all traffic
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

app.use(express.static(path.join(__dirname, 'docs')));
// Add CORS headers for /pdfs route
// Improved CORS for /pdfs route
app.use('/pdfs', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); 
  res.header('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});
app.use('/pdfs', express.static('/data/pdfs'));


// Error handler for CORS
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({ error: 'CORS error: Origin not allowed' });
  } else {
    next(err);
  }
});

// Basic error logging middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  if (err.stack) {
    console.error(err.stack);
  }
  res.status(500).json({ error: 'Internal server error' });
});

app.use(require('cookie-parser')());

// Webhook handler (must use raw body)
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  console.log('--- Stripe Webhook Received ---');
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_email;
    const stripeId = session.id;
    console.log('--- Stripe Webhook Event ---');
    console.log('Session:', JSON.stringify(session, null, 2));
    console.log('Email:', email);
    console.log('StripeId:', stripeId);
    try {
      // Find or create user
      let user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
        user = await prisma.user.create({
          data: { email, password: '' }
        });
        console.log('Created new user:', user);
      } else {
        console.log('Found user:', user);
      }

      const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
      console.log('Line Items:', lineItems.data);
      for (const item of lineItems.data) {
        const issueInfo = ISSUE_MAP[item.price.id];
        console.log('PriceId:', item.price.id, 'IssueInfo:', issueInfo);
        if (issueInfo) {
          // Find the Issue in the database by title
          const issue = await prisma.issue.findUnique({ where: { title: issueInfo.name } });
          console.log('DB Issue lookup result:', issue);
          if (!issue) {
            console.warn(`No matching Issue in DB for title: ${issueInfo.name}`);
            continue;
          }
          // Prevent duplicate purchases by stripeId
          const existing = await prisma.purchase.findUnique({ where: { stripeId } });
          console.log('Existing purchase for stripeId:', existing);
          if (!existing) {
            try {
              const purchase = await prisma.purchase.create({
                data: {
                  userId: user.id,
                  issueId: issue.id,
                  stripeId: stripeId
                }
              });
              console.log('Created purchase:', purchase);
              purchases[session.id] = {
                issueId: issue.id,
                issueName: issue.title,
                pdfPath: issue.pdfPath,
              };
              console.log(`Purchased: ${issue.title} for user ${email}`);
            } catch (err) {
              console.error('Error creating purchase:', err);
            }
          } else {
            console.log(`Purchase already exists for stripeId: ${stripeId}`);
          }
        } else {
          console.warn(`Unknown Price ID in webhook: ${item.price.id}`);
        }
      }
    } catch (e) {
      console.error('Error processing purchase:', e);
    }
  }

  res.sendStatus(200);
});

app.use(express.json()); // must come after /webhook

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { ISSUES } = require('./issues');
const ISSUE_MAP = {};
for (const issue of ISSUES) {
  ISSUE_MAP[issue.priceId] = {
    name: issue.title,
    pdfPath: issue.pdfPath
  };
}

const { router: authRoutes, requireAuth } = require('./auth');
app.use('/auth', authRoutes);

// Create checkout session route
app.post('/create-checkout-session', requireAuth, async (req, res) => {
  try {
    const { priceId } = req.body;
    if (!priceId || !ISSUE_MAP[priceId]) {
      return res.status(400).json({ error: 'Invalid or unknown priceId' });
    }
    // Determine base URL for redirect
    const isLocal = req.headers.origin && req.headers.origin.includes('localhost');
    const baseUrl = isLocal
      ? `http://localhost:${PORT}`
      : process.env.ALLOWED_ORIGIN;

    // Get user from JWT
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: user.email,
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      success_url: `${baseUrl}/payment_success.html`,
      cancel_url: `${baseUrl}/payment_cancel.html`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Error creating checkout session:', err);
    res.status(500).json({ error: err.message });
  }
});

// Frontend will call this after redirect with ?session_id=...
const purchases = {};
app.get('/purchase-status/:sessionId', (req, res) => {
  const record = purchases[req.params.sessionId];
  if (!record) return res.status(404).json({ error: 'No purchase found' });
  res.json(record);
});


