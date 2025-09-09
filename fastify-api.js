
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
  // Stripe webhook (raw body)
  fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, function (req, body, done) {
    done(null, body);
  });

  /**
   * Stripe webhook endpoint
   * @route POST /webhook
   */
  fastify.post('/webhook', async (request, reply) => {
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
    try {
      const { priceId } = request.body;
      // Find the issue by either live or test priceId
      const issue = ISSUES.find(i => i.priceIdLive === priceId || i.priceIdTest === priceId);
      if (!issue) {
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
        return reply.status(401).send({ error: 'User not found' });
      }

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
      reply.send({ url: session.url });
    } catch (err) {
      fastify.log.error('Error creating checkout session:', err);
      reply.status(500).send({ error: 'Internal server error' });
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
