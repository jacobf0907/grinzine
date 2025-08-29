console.log("Starting server...");
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
const app = express();
app.use(express.static(path.join(__dirname, 'docs')));
app.use('/pdfs', express.static(path.join(__dirname, 'pdfs')));
// Parse cookies globally for all routes
app.use(require('cookie-parser')());
// Parse JSON bodies globally (except for /webhook)
app.use(express.json());

// port 4242 for local development, port will be set by Render for production
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

//mount router in main server
const { router: authRoutes, requireAuth } = require('./auth');
app.use('/auth', authRoutes);

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

module.exports = prisma;

async function testPrisma() {
// Create a user
await prisma.user.create({
  data: { email: "test@example.com", password: "hashedpassword" }
});

// Find user
const user = await prisma.user.findUnique({ where: { email: "test@example.com" } });
  console.log(user);
}


// Allow your GitHub Pages site to call the API
const ALLOWED_ORIGINS = [
  process.env.ALLOWED_ORIGIN,
  `http://localhost:${PORT}` // use the PORT variable for localhost
];

app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') return next(); // keep raw body for Stripe
  cors({
    origin: function(origin, callback) {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true
  })(req, res, next);
});


// Map Stripe Price IDs to issue info
const ISSUE_MAP = {
  'price_1RugTbJulbntxSe8oz8G1wql': {
    name: 'GRIN Zine - Issue 1',
    pdfPath: '/pdfs/grin-magazine-volume-one-web.pdf'
  },
// add new issues here
};


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

// Webhook handler (must use raw body)
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
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
          data: { email, password: '' } // password blank since Stripe signup
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

// Frontend will call this after redirect with ?session_id=...
app.get('/purchase-status/:sessionId', (req, res) => {
  const record = purchases[req.params.sessionId];
  if (!record) return res.status(404).json({ error: 'No purchase found' });
  res.json(record);
});


