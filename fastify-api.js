// (Removed monkey-patch for fastify.post. Debug log is in the correct handler.)
// fastify-api.js

const fp = require('fastify-plugin');
const Stripe = require('stripe');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { ISSUES } = require('./issues');
const PORT = process.env.PORT || 4242;

// DEBUG: Log env vars at plugin load (stringified for log visibility)
console.log('[fastify-api.js] ENV at module load: ' + JSON.stringify({
  STRIPE_MODE: process.env.STRIPE_MODE,
  STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE ? '[set]' : '[not set]',
  STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST ? '[set]' : '[not set]',
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ? '[set]' : '[not set]',
  ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
  NODE_ENV: process.env.NODE_ENV
}));

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

console.log('DEBUG: process.env at module load:', process.env);

async function apiPlugin(fastify, opts) {
  /**
   * Stripe webhook endpoint
   * @route POST /webhook
   */
  // DEBUG: Log env vars at plugin registration
  fastify.log.info('[fastify-api.js] ENV at plugin registration: ' + JSON.stringify({
    STRIPE_MODE: process.env.STRIPE_MODE,
    STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE ? '[set]' : '[not set]',
    STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST ? '[set]' : '[not set]',
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ? '[set]' : '[not set]',
    ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
    NODE_ENV: process.env.NODE_ENV
  }));
  fastify.route({
    method: 'POST',
    url: '/webhook',
    config: {},
    schema: {},
    // Only for this route, override the content type parser
    bodyLimit: 1048576, // 1MB
    handler: async (request, reply) => {
      fastify.log.info('[fastify-api.js] /webhook handler ENV: ' + JSON.stringify({
        STRIPE_MODE: process.env.STRIPE_MODE,
        STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE ? '[set]' : '[not set]',
        STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST ? '[set]' : '[not set]',
        STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ? '[set]' : '[not set]',
        ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
        NODE_ENV: process.env.NODE_ENV
      }));
      try {
        fastify.log.info('--- Stripe Webhook Received ---');
        // Always get env vars at request time
        const STRIPE_MODE = process.env.STRIPE_MODE || 'live';
        const STRIPE_SECRET_KEY = STRIPE_MODE === 'live'
          ? process.env.STRIPE_SECRET_KEY_LIVE
          : process.env.STRIPE_SECRET_KEY_TEST;
        const STRIPE_WEBHOOK_SECRET = STRIPE_MODE === 'live'
          ? process.env.STRIPE_WEBHOOK_SECRET_LIVE
          : process.env.STRIPE_WEBHOOK_SECRET_TEST;
        const stripe = Stripe(STRIPE_SECRET_KEY);
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
    fastify.log.info('[fastify-api.js] /create-checkout-session handler ENV: ' + JSON.stringify({
      STRIPE_MODE: process.env.STRIPE_MODE,
      STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE ? '[set]' : '[not set]',
      STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST ? '[set]' : '[not set]',
      STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ? '[set]' : '[not set]',
      ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN,
      NODE_ENV: process.env.NODE_ENV
    }));
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

module.exports = fp(apiPlugin, { encapsulate: false });
