// minimal-server.js
const Fastify = require('fastify');

const app = Fastify({ logger: true });

// Debug route to return all environment variables
app.get('/env-debug', async (request, reply) => {
  app.log.info('[ENV-DEBUG] ENV KEYS:', Object.keys(process.env));
  app.log.info('[ENV-DEBUG] TEST_SECRET:', process.env.TEST_SECRET);
  return process.env;
});

// Minimal /create-checkout-session-test route for env var testing
app.post('/create-checkout-session-test', async (request, reply) => {
  const envKeys = Object.keys(process.env);
  reply.send({
    envKeys,
    TEST_SECRET: process.env.TEST_SECRET,
    STRIPE_SECRET_KEY_TEST: process.env.STRIPE_SECRET_KEY_TEST,
    STRIPE_SECRET_KEY_LIVE: process.env.STRIPE_SECRET_KEY_LIVE,
  });
});

const PORT = process.env.PORT || 8080;
app.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) {
    app.log.error(err);
    process.exit(1);
  }
  app.log.info(`Minimal Fastify server listening on ${address}`);
});
