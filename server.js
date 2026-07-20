require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const Stripe = require('stripe');

// ==== CONFIGURATION ====
// The Stripe secret key is loaded from a separate .env file on the server,
// never stored in this code file directly. See setup instructions.
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

// This is the Price ID for your $1.99/month subscription, already created
const PRICE_ID = 'price_1TvBBi0AAx3O9Jr1ePW2Rdky';

// Free word limit before an account/payment is required
const FREE_WORD_LIMIT = 500;

const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

const stripe = Stripe(STRIPE_SECRET_KEY);
const app = express();

// Allow requests from your actual website domains
app.use(cors({
  origin: ['https://hellolasna.com', 'https://www.hellolasna.com', 'https://lasna20226.github.io']
}));

// ==== DATABASE SETUP ====
const db = new Database('/root/lasna-backend/lasna.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    word_count INTEGER DEFAULT 0,
    is_subscribed INTEGER DEFAULT 0,
    stripe_customer_id TEXT
  )
`);

// ==== ROUTES ====

// Stripe webhook needs the RAW request body, so this route is registered
// BEFORE the express.json() middleware below, using its own raw parser.
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // Verifies this request genuinely came from Stripe, not an impersonator
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_email || session.customer_details?.email;
    if (email) {
      db.prepare(`
        INSERT INTO users (email, is_subscribed, stripe_customer_id)
        VALUES (?, 1, ?)
        ON CONFLICT(email) DO UPDATE SET is_subscribed = 1, stripe_customer_id = ?
      `).run(email, session.customer, session.customer);
      console.log(`Marked ${email} as subscribed.`);
    }
  }

  res.json({ received: true });
});

// Everything below this line can read normal JSON request bodies
app.use(express.json());

// Check and update someone's word usage. Called every time they check writing.
app.post('/api/check-usage', (req, res) => {
  const { email, wordCount } = req.body;

  if (!email) {
    // No account yet - this is fine, just means they haven't hit the limit,
    // since accounts are only created once someone exceeds 500 words total.
    return res.json({ requiresAccount: false, totalWords: wordCount });
  }

  const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!existing) {
    db.prepare('INSERT INTO users (email, word_count) VALUES (?, ?)').run(email, wordCount);
    return res.json({ requiresPayment: false, totalWords: wordCount });
  }

  const newTotal = existing.word_count + wordCount;
  db.prepare('UPDATE users SET word_count = ? WHERE email = ?').run(newTotal, email);

  const requiresPayment = newTotal > FREE_WORD_LIMIT && !existing.is_subscribed;

  res.json({ requiresPayment, totalWords: newTotal, isSubscribed: !!existing.is_subscribed });
});

// Creates a Stripe Checkout session for someone ready to subscribe
app.post('/api/create-checkout-session', async (req, res) => {
  const { email } = req.body;

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: email,
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: 'https://hellolasna.com?payment=success',
      cancel_url: 'https://hellolasna.com?payment=cancelled',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout session error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Simple health check, useful for confirming the server is running
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`LASNA backend running on port ${PORT}`);
});
