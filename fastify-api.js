
// fastify-api.js
const fp = require('fastify-plugin');
const Stripe = require('stripe');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { ISSUES } = require('./issues');

const STRIPE_MODE = process.env.STRIPE_MODE || 'live';
const STRIPE_SECRET_KEY = STRIPE_MODE === 'live'
  ? process.env.STRIPE_SECRET_KEY_LIVE
  : process.env.STRIPE_SECRET_KEY_TEST;
const STRIPE_WEBHOOK_SECRET = STRIPE_MODE === 'live'
  ? process.env.STRIPE_WEBHOOK_SECRET_LIVE
  : process.env.STRIPE_WEBHOOK_SECRET_TEST;
const stripe = Stripe(STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 4242;

const ISSUE_MAP = {};
for (const issue of ISSUES) {
  if (issue.priceIdLive) {
    ISSUE_MAP[issue.priceIdLive] = {
      name: issue.title,
      pdfPath: issue.pdfPath
    };
  }
  if (issue.priceIdTest) {
    ISSUE_MAP[issue.priceIdTest] = {
      name: issue.title,
      pdfPath: issue.pdfPath
    };
  }
}


async function apiPlugin(fastify, opts) {
  /**
   * Stripe webhook endpoint
   * @route POST /webhook
   */
  fastify.route({
    method: 'POST',
    url: '/webhook',
    config: {},
    schema: {},
    // Only for this route, override the content type parser
    bodyLimit: 1048576, // 1MB
    handler: async (request, reply) => {
      try {
        fastify.log.info('--- Stripe Webhook Received ---');
        const sig = request.headers['stripe-signature'];
        let event;
        try {
          event = stripe.webhooks.constructEvent(request.body, sig, STRIPE_WEBHOOK_SECRET);
        } catch (err) {
          fastify.log.error('Webhook signature verification failed:', err.message);
          return reply.status(400).send(`Webhook Error: ${err.message}`);
        }

        if (event.type === 'checkout.session.completed') {
          const session = event.data.object;
          const email = session.customer_email;
          const stripeId = session.id;
          fastify.log.info('--- Stripe Webhook Event ---');
          // Mask sensitive data in logs for production
          fastify.log.info('Email:', email);
          fastify.log.info('StripeId:', stripeId);
          try {
            // Find or create user
            let user = await prisma.user.findUnique({ where: { email } });
            if (!user) {
              user = await prisma.user.create({ data: { email, password: '' } });
              fastify.log.info('Created new user:', user.id);
            } else {
              fastify.log.info('Found user:', user.id);
            }

            const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
            for (const item of lineItems.data) {
              const issueInfo = ISSUE_MAP[item.price.id];
              fastify.log.info('PriceId:', item.price.id, 'IssueInfo:', issueInfo ? issueInfo.name : 'Unknown');
              if (issueInfo) {
                // Find the Issue in the database by title
                const issue = await prisma.issue.findUnique({ where: { title: issueInfo.name } });
                if (!issue) {
                  fastify.log.warn(`No matching Issue in DB for title: ${issueInfo.name}`);
                  continue;
                }
                // Prevent duplicate purchases by stripeId
                const existing = await prisma.purchase.findUnique({ where: { stripeId } });
                if (!existing) {
                  try {
                    await prisma.purchase.create({
                      data: {
                        userId: user.id,
                        issueId: issue.id,
                        stripeId: stripeId
                      }
                    });
                    fastify.log.info(`Purchased: ${issue.title} for user ${email}`);
                  } catch (err) {
                    fastify.log.error('Error creating purchase:', err);
                  }
                } else {
                  fastify.log.info(`Purchase already exists for stripeId: ${stripeId}`);
                }
              } else {
                fastify.log.warn(`Unknown Price ID in webhook: ${item.price.id}`);
              }
            }
          } catch (e) {
            fastify.log.error('Error processing purchase:', e);
          }
        }

        reply.code(200).send();
      } catch (err) {
        fastify.log.error('Webhook handler error:', err);
        reply.status(500).send({ error: 'Internal server error' });
      }
    },
    // This attaches a content type parser only for this route
    preHandler: (request, reply, done) => {
      // Override content type parser for this route only
      request.rawBody = '';
      request.raw.on('data', (chunk) => {
        request.rawBody += chunk;
      });
      request.raw.on('end', () => {
        request.body = Buffer.from(request.rawBody);
        done();
      });
    }
  });

  /**
   * Purchase status route (now uses DB)
   * @route GET /purchase-status/:sessionId
   */
  fastify.get('/purchase-status/:sessionId', {
    schema: {
      params: {
        type: 'object',
        properties: {
          sessionId: { type: 'string', pattern: '^[\\w-]+$' }
        },
        required: ['sessionId']
      }
    }
  }, async (request, reply) => {
    try {
      const { sessionId } = request.params;
      // Find purchase by stripeId and join Issue
      const purchase = await prisma.purchase.findUnique({
        where: { stripeId: sessionId },
        include: { issue: true }
      });
      if (!purchase) return reply.status(404).send({ error: 'No purchase found' });
      reply.send({
        issueId: purchase.issueId,
        issueName: purchase.issue.title,
        pdfPath: purchase.issue.pdfPath
      });
    } catch (err) {
      fastify.log.error('Error in purchase-status:', err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  // Helper: requireAuth (reuse from fastify)
  const requireAuth = fastify.requireAuth;

  /**
   * Create checkout session route (protected)
   * @route POST /create-checkout-session
   */
  fastify.post('/create-checkout-session', {
    preHandler: requireAuth,
    schema: {
      body: {
        type: 'object',
        properties: {
          priceId: { type: 'string' }
        },
        required: ['priceId']
      }
    }
  }, async (request, reply) => {
    // Log all environment variables at request time
    fastify.log.info('[CHECKOUT] STRIPE ENV VARS:', {
      STRIPE_MODE: process.env.STRIPE_MODE,
      STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE,
      STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST,
      STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY
    });
    // Dynamically read Stripe env vars and create Stripe instance
    const STRIPE_MODE = process.env.STRIPE_MODE || 'live';
    const STRIPE_SECRET_KEY = STRIPE_MODE === 'live'
      ? process.env.STRIPE_SECRET_KEY_LIVE
      : process.env.STRIPE_SECRET_KEY_TEST;
    const stripe = Stripe(STRIPE_SECRET_KEY);
    fastify.log.info('[CHECKOUT] Incoming request body:', request.body);
    fastify.log.info('[CHECKOUT] Authenticated userId:', request.userId);
    fastify.log.info('[CHECKOUT] STRIPE_MODE:', STRIPE_MODE);
    fastify.log.info('[CHECKOUT] STRIPE_SECRET_KEY:', STRIPE_SECRET_KEY ? '[set]' : '[not set]');
    try {
      const { priceId } = request.body;
      // Find the issue by either live or test priceId
      const issue = ISSUES.find(i => i.priceIdLive === priceId || i.priceIdTest === priceId);
      if (!issue) {
        fastify.log.warn('[CHECKOUT] Invalid or unknown priceId:', priceId);
        return reply.status(400).send({ error: 'Invalid or unknown priceId' });
      }
      // Select correct priceId for current mode
      const selectedPriceId = STRIPE_MODE === 'live' ? issue.priceIdLive : issue.priceIdTest;

      // Determine base URL for redirect
      const isLocal = request.headers.origin && request.headers.origin.includes('localhost');
      const baseUrl = isLocal
        ? `http://localhost:${PORT}`
        : process.env.ALLOWED_ORIGIN;

      // Get user from JWT
      const user = await prisma.user.findUnique({ where: { id: request.userId } });
      if (!user) {
        fastify.log.warn('[CHECKOUT] User not found for userId:', request.userId);
        return reply.status(401).send({ error: 'User not found' });
      }

      fastify.log.info('[CHECKOUT] Creating Stripe session with:', {
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
      fastify.log.info('[CHECKOUT] Stripe session created:', session.id);
      reply.send({ url: session.url });
    } catch (err) {
      if (!err) {
        fastify.log.error('Checkout session error: err is undefined or null!');
      }
      fastify.log.error('[CHECKOUT] STRIPE_MODE:', STRIPE_MODE);
      fastify.log.error('[CHECKOUT] STRIPE_SECRET_KEY:', STRIPE_SECRET_KEY ? '[set]' : '[not set]');
      fastify.log.error('[CHECKOUT] Error creating checkout session:', err);
      fastify.log.error('[CHECKOUT] Error as string:', String(err));
      fastify.log.error('[CHECKOUT] Error type:', typeof err);
      if (err && err.stack) fastify.log.error('[CHECKOUT] Stack trace:', err.stack);
      if (err && typeof err === 'object') fastify.log.error('[CHECKOUT] Error object:', JSON.stringify(err, null, 2));
      // Try to log the error using util.inspect for deep objects
      try {
        const util = require('util');
        fastify.log.error('[CHECKOUT] Error (util.inspect):', util.inspect(err, { depth: 5 }));
      } catch (e) {}
      reply.status(500).send({ error: 'Internal server error', details: err && err.message });
    }
  });

  /**
   * Subscribe route
   * @route POST /subscribe
   */
  fastify.post('/subscribe', {
    schema: {
      body: {
        type: 'object',
        properties: {
          email: { type: 'string', format: 'email' },
          name: { type: 'string', minLength: 1 }
        },
        required: ['email', 'name']
      }
    }
  }, async (request, reply) => {
    try {
      const { email, name } = request.body;
      // ...handle subscription logic...
      reply.send({ message: 'Subscription successful!' });
    } catch (err) {
      fastify.log.error('Error in subscribe:', err);
      reply.status(500).send({ error: 'Internal server error' });
    }
  });

  // Add more routes (checkout session, purchase-status, etc.) here...
}

module.exports = fp(apiPlugin);
