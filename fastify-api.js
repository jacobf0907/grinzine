// (Removed monkey-patch for fastify.post. Debug log is in the correct handler.)
// fastify-api.js

const fp = require('fastify-plugin');
const Stripe = require('stripe');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { ISSUES } = require('./issues');
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
