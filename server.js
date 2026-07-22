require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const Stripe = require('stripe');
const bcrypt = require('bcrypt');

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
    password_hash TEXT,
    word_count INTEGER DEFAULT 0,
    is_subscribed INTEGER DEFAULT 0,
    stripe_customer_id TEXT,
    user_type TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
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

// ==== ACCOUNTS: SIGN UP ====
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (existing && existing.password_hash) {
    return res.status(400).json({ error: 'An account with this email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  if (existing) {
    // They already have a row from tracking free words, just add the password now
    db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(passwordHash, email);
  } else {
    db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);
  }

  res.json({ success: true });
});

// ==== ACCOUNTS: LOG IN ====
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || !user.password_hash) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  const passwordMatches = await bcrypt.compare(password, user.password_hash);

  if (!passwordMatches) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  res.json({
    success: true,
    email: user.email,
    isSubscribed: !!user.is_subscribed,
    wordCount: user.word_count,
    userType: user.user_type
  });
});

// ==== ACCOUNTS: SET AUTHOR OR STUDENT ====
app.post('/api/set-user-type', (req, res) => {
  const { email, userType } = req.body;

  if (!email || (userType !== 'author' && userType !== 'student')) {
    return res.status(400).json({ error: 'A valid email and userType (author or student) are required.' });
  }

  db.prepare('UPDATE users SET user_type = ? WHERE email = ?').run(userType, email);
  res.json({ success: true });
});

// ==== DOCUMENTS: SAVE (creates new, or updates existing if documentId given) ====
app.post('/api/save-document', (req, res) => {
  const { email, documentId, title, content } = req.body;

  if (!email || !title) {
    return res.status(400).json({ error: 'Email and title are required.' });
  }

  if (documentId) {
    const existing = db.prepare('SELECT * FROM documents WHERE id = ? AND email = ?').get(documentId, email);
    if (!existing) {
      return res.status(404).json({ error: 'Document not found.' });
    }
    db.prepare('UPDATE documents SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(title, content, documentId);
    return res.json({ success: true, documentId: documentId });
  } else {
    const result = db.prepare('INSERT INTO documents (email, title, content) VALUES (?, ?, ?)')
      .run(email, title, content);
    return res.json({ success: true, documentId: result.lastInsertRowid });
  }
});

// ==== DOCUMENTS: LIST all of a user's saved documents ====
app.get('/api/documents', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const docs = db.prepare('SELECT id, title, updated_at FROM documents WHERE email = ? ORDER BY updated_at DESC').all(email);
  res.json({ documents: docs });
});

// ==== DOCUMENTS: LOAD one specific document's full content ====
app.get('/api/document/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const doc = db.prepare('SELECT * FROM documents WHERE id = ? AND email = ?').get(id, email);
  if (!doc) {
    return res.status(404).json({ error: 'Document not found.' });
  }
  res.json({ document: doc });
});

// ==== DOCUMENTS: DELETE ====
app.delete('/api/document/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM documents WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Document not found.' });
  }
  db.prepare('DELETE FROM documents WHERE id = ?').run(id);
  res.json({ success: true });
});

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
