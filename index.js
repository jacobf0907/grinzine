require('dotenv').config();
const express = require('express');
const cors = requrie('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
const app = express();
// Use PORT = 4242 for local development
// const PORT = 4242;


// Allow your GitHub Pages site to call the API
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN; //
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') return next(); // keep raw body for Stripe
  cors({ origin: ALLOWED_ORIGIN })(req, res, () => {
    express.json()(req, res, next);
  });
});


// Map Stripe Price IDs to issue info
const ISSUE_MAP = {
  'price_1RugTbJulbntxSe8oz8G1wql': {
    name: 'GRIN Zine - Issue 1',
    pdfPath: '/issues/issue1.pdf'
  },
  // Add more issues like this:
  // 'price_XXXXXXXXXXXX': {
  //   name: 'GRIN Zine - Issue 2',
  //   pdfPath: '/issues/issue2.pdf'
  // },
  // 'price_YYYYYYYYYYYY': {
  //   name: 'GRIN Zine - Issue 3',
  //   pdfPath: '/issues/issue3.pdf'
  // },
};

// Temp in-memory store (use a DB later)
const purchases = {};

// Serve static files only from the 'public' directory for safety
app.use(express.static(path.join(__dirname, 'public')));

// Create checkout session route
app.post('/create-checkout-session', async (req, res) => {
  try {
    const { priceId } = req.body;
    if (!priceId || !ISSUE_MAP[priceId]) {
      return res.status(400).json({ error: 'Invalid or unknown priceId' });
    }
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      success_url: 'https://jacobf0907.github.io/grinzine//payment_success.html',
      cancel_url: 'https://jacobf0907.github.io/grinzine//payment_cancel.html',
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
    try {
      const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
      lineItems.data.forEach(item => {
        const issue = ISSUE_MAP[item.price.id];
        if (issue) {
          purchases[session.id] = {
            priceId: item.price.id,
            issueName: issue.name,
            pdfPath: issue.pdfPath,
          };
          console.log(`Purchased: ${issue.name}`);
        } else {
          console.warn(`Unknown Price ID in webhook: ${item.price.id}`);
        }
      });
    } catch (e) {
      console.error('Error fetching line items:', e);
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

// port 4242 for local development, port will be set by Render for production
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

