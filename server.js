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

db.exec(`
  CREATE TABLE IF NOT EXISTS world_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS characters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT,
    age TEXT,
    appearance TEXT,
    personality TEXT,
    motivation TEXT,
    relationships TEXT,
    backstory TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    title TEXT NOT NULL,
    date_label TEXT,
    sort_order INTEGER DEFAULT 0,
    description TEXT,
    characters_involved TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS plot_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    color TEXT DEFAULT '#1e3a8a',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS plot_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    thread_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS outline_sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    title TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS outline_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    section_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,
    sort_order INTEGER DEFAULT 0,
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

// ==== OUTLINE SECTIONS: SAVE ====
app.post('/api/outline-section', (req, res) => {
  const { email, title, sortOrder } = req.body;
  if (!email || !title) {
    return res.status(400).json({ error: 'Email and title are required.' });
  }
  const order = sortOrder !== undefined && sortOrder !== null && sortOrder !== "" ? parseInt(sortOrder, 10) : 0;
  const result = db.prepare('INSERT INTO outline_sections (email, title, sort_order) VALUES (?, ?, ?)').run(email, title, order);
  res.json({ success: true, sectionId: result.lastInsertRowid });
});

// ==== OUTLINE SECTIONS: LIST ====
app.get('/api/outline-sections', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const sections = db.prepare('SELECT * FROM outline_sections WHERE email = ? ORDER BY sort_order ASC, id ASC').all(email);
  res.json({ sections: sections });
});

// ==== OUTLINE SECTIONS: DELETE (also deletes its items) ====
app.delete('/api/outline-section/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM outline_sections WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Section not found.' });
  }
  db.prepare('DELETE FROM outline_items WHERE section_id = ? AND email = ?').run(id, email);
  db.prepare('DELETE FROM outline_sections WHERE id = ?').run(id);
  res.json({ success: true });
});

// ==== OUTLINE ITEMS: SAVE (creates new, or updates existing if itemId given) ====
app.post('/api/outline-item', (req, res) => {
  const { email, itemId, sectionId, title, summary, sortOrder } = req.body;

  if (!email || !sectionId || !title) {
    return res.status(400).json({ error: 'Email, sectionId, and title are required.' });
  }

  const order = sortOrder !== undefined && sortOrder !== null && sortOrder !== "" ? parseInt(sortOrder, 10) : 0;

  if (itemId) {
    const existing = db.prepare('SELECT * FROM outline_items WHERE id = ? AND email = ?').get(itemId, email);
    if (!existing) {
      return res.status(404).json({ error: 'Item not found.' });
    }
    db.prepare('UPDATE outline_items SET title = ?, summary = ?, sort_order = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(title, summary, order, itemId);
    return res.json({ success: true, itemId: itemId });
  } else {
    const result = db.prepare('INSERT INTO outline_items (email, section_id, title, summary, sort_order) VALUES (?, ?, ?, ?, ?)')
      .run(email, sectionId, title, summary, order);
    return res.json({ success: true, itemId: result.lastInsertRowid });
  }
});

// ==== OUTLINE ITEMS: LIST all items across all sections (frontend groups them) ====
app.get('/api/outline-items', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const items = db.prepare('SELECT * FROM outline_items WHERE email = ? ORDER BY section_id ASC, sort_order ASC').all(email);
  res.json({ items: items });
});

// ==== OUTLINE ITEMS: DELETE ====
app.delete('/api/outline-item/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM outline_items WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Item not found.' });
  }
  db.prepare('DELETE FROM outline_items WHERE id = ?').run(id);
  res.json({ success: true });
});

// ==== PLOT THREADS: SAVE (create only, threads are simple - name + color) ====
app.post('/api/plot-thread', (req, res) => {
  const { email, name, color } = req.body;
  if (!email || !name) {
    return res.status(400).json({ error: 'Email and name are required.' });
  }
  const result = db.prepare('INSERT INTO plot_threads (email, name, color) VALUES (?, ?, ?)').run(email, name, color || '#1e3a8a');
  res.json({ success: true, threadId: result.lastInsertRowid });
});

// ==== PLOT THREADS: LIST ====
app.get('/api/plot-threads', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const threads = db.prepare('SELECT * FROM plot_threads WHERE email = ? ORDER BY id ASC').all(email);
  res.json({ threads: threads });
});

// ==== PLOT THREADS: DELETE (also deletes its entries) ====
app.delete('/api/plot-thread/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM plot_threads WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Thread not found.' });
  }
  db.prepare('DELETE FROM plot_entries WHERE thread_id = ? AND email = ?').run(id, email);
  db.prepare('DELETE FROM plot_threads WHERE id = ?').run(id);
  res.json({ success: true });
});

// ==== PLOT ENTRIES: SAVE (creates new, or updates existing if entryId given) ====
app.post('/api/plot-entry', (req, res) => {
  const { email, entryId, threadId, title, description, sortOrder } = req.body;

  if (!email || !threadId || !title) {
    return res.status(400).json({ error: 'Email, threadId, and title are required.' });
  }

  const order = sortOrder !== undefined && sortOrder !== null && sortOrder !== "" ? parseInt(sortOrder, 10) : 0;

  if (entryId) {
    const existing = db.prepare('SELECT * FROM plot_entries WHERE id = ? AND email = ?').get(entryId, email);
    if (!existing) {
      return res.status(404).json({ error: 'Entry not found.' });
    }
    db.prepare('UPDATE plot_entries SET title = ?, description = ?, sort_order = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(title, description, order, entryId);
    return res.json({ success: true, entryId: entryId });
  } else {
    const result = db.prepare('INSERT INTO plot_entries (email, thread_id, title, description, sort_order) VALUES (?, ?, ?, ?, ?)')
      .run(email, threadId, title, description, order);
    return res.json({ success: true, entryId: result.lastInsertRowid });
  }
});

// ==== PLOT ENTRIES: LIST all entries across all threads (frontend groups them by thread) ====
app.get('/api/plot-entries', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const entries = db.prepare('SELECT * FROM plot_entries WHERE email = ? ORDER BY thread_id ASC, sort_order ASC').all(email);
  res.json({ entries: entries });
});

// ==== PLOT ENTRIES: DELETE ====
app.delete('/api/plot-entry/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM plot_entries WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Entry not found.' });
  }
  db.prepare('DELETE FROM plot_entries WHERE id = ?').run(id);
  res.json({ success: true });
});

// ==== TIMELINE: SAVE (creates new, or updates existing if eventId given) ====
app.post('/api/timeline-event', (req, res) => {
  const { email, eventId, title, dateLabel, sortOrder, description, charactersInvolved } = req.body;

  if (!email || !title) {
    return res.status(400).json({ error: 'Email and title are required.' });
  }

  const order = sortOrder !== undefined && sortOrder !== null && sortOrder !== "" ? parseInt(sortOrder, 10) : 0;

  if (eventId) {
    const existing = db.prepare('SELECT * FROM timeline_events WHERE id = ? AND email = ?').get(eventId, email);
    if (!existing) {
      return res.status(404).json({ error: 'Event not found.' });
    }
    db.prepare(`UPDATE timeline_events SET title = ?, date_label = ?, sort_order = ?, description = ?,
      characters_involved = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(title, dateLabel, order, description, charactersInvolved, eventId);
    return res.json({ success: true, eventId: eventId });
  } else {
    const result = db.prepare(`INSERT INTO timeline_events (email, title, date_label, sort_order, description, characters_involved)
      VALUES (?, ?, ?, ?, ?, ?)`)
      .run(email, title, dateLabel, order, description, charactersInvolved);
    return res.json({ success: true, eventId: result.lastInsertRowid });
  }
});

// ==== TIMELINE: LIST all of a user's events, ordered by sort_order ====
app.get('/api/timeline-events', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const events = db.prepare('SELECT * FROM timeline_events WHERE email = ? ORDER BY sort_order ASC, id ASC').all(email);
  res.json({ events: events });
});

// ==== TIMELINE: DELETE ====
app.delete('/api/timeline-event/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM timeline_events WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Event not found.' });
  }
  db.prepare('DELETE FROM timeline_events WHERE id = ?').run(id);
  res.json({ success: true });
});

// ==== CHARACTERS: SAVE (creates new, or updates existing if characterId given) ====
app.post('/api/character', (req, res) => {
  const { email, characterId, name, role, age, appearance, personality, motivation, relationships, backstory } = req.body;

  if (!email || !name) {
    return res.status(400).json({ error: 'Email and name are required.' });
  }

  if (characterId) {
    const existing = db.prepare('SELECT * FROM characters WHERE id = ? AND email = ?').get(characterId, email);
    if (!existing) {
      return res.status(404).json({ error: 'Character not found.' });
    }
    db.prepare(`UPDATE characters SET name = ?, role = ?, age = ?, appearance = ?, personality = ?,
      motivation = ?, relationships = ?, backstory = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(name, role, age, appearance, personality, motivation, relationships, backstory, characterId);
    return res.json({ success: true, characterId: characterId });
  } else {
    const result = db.prepare(`INSERT INTO characters (email, name, role, age, appearance, personality, motivation, relationships, backstory)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(email, name, role, age, appearance, personality, motivation, relationships, backstory);
    return res.json({ success: true, characterId: result.lastInsertRowid });
  }
});

// ==== CHARACTERS: LIST all of a user's characters ====
app.get('/api/characters', (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const chars = db.prepare('SELECT id, name, role, updated_at FROM characters WHERE email = ? ORDER BY name ASC').all(email);
  res.json({ characters: chars });
});

// ==== CHARACTERS: LOAD one specific character's full profile ====
app.get('/api/character/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const character = db.prepare('SELECT * FROM characters WHERE id = ? AND email = ?').get(id, email);
  if (!character) {
    return res.status(404).json({ error: 'Character not found.' });
  }
  res.json({ character: character });
});

// ==== CHARACTERS: DELETE ====
app.delete('/api/character/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM characters WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Character not found.' });
  }
  db.prepare('DELETE FROM characters WHERE id = ?').run(id);
  res.json({ success: true });
});

// ==== WORLD-BUILDING: SAVE (creates new, or updates existing if entryId given) ====
app.post('/api/world-entry', (req, res) => {
  const { email, entryId, category, title, content } = req.body;

  if (!email || !category || !title) {
    return res.status(400).json({ error: 'Email, category, and title are required.' });
  }

  if (entryId) {
    const existing = db.prepare('SELECT * FROM world_entries WHERE id = ? AND email = ?').get(entryId, email);
    if (!existing) {
      return res.status(404).json({ error: 'Entry not found.' });
    }
    db.prepare('UPDATE world_entries SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(title, content, entryId);
    return res.json({ success: true, entryId: entryId });
  } else {
    const result = db.prepare('INSERT INTO world_entries (email, category, title, content) VALUES (?, ?, ?, ?)')
      .run(email, category, title, content);
    return res.json({ success: true, entryId: result.lastInsertRowid });
  }
});

// ==== WORLD-BUILDING: LIST entries, optionally filtered by category ====
app.get('/api/world-entries', (req, res) => {
  const email = req.query.email;
  const category = req.query.category;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  var entries;
  if (category) {
    entries = db.prepare('SELECT id, category, title, updated_at FROM world_entries WHERE email = ? AND category = ? ORDER BY updated_at DESC').all(email, category);
  } else {
    entries = db.prepare('SELECT id, category, title, updated_at FROM world_entries WHERE email = ? ORDER BY updated_at DESC').all(email);
  }
  res.json({ entries: entries });
});

// ==== WORLD-BUILDING: LOAD one specific entry's full content ====
app.get('/api/world-entry/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const entry = db.prepare('SELECT * FROM world_entries WHERE id = ? AND email = ?').get(id, email);
  if (!entry) {
    return res.status(404).json({ error: 'Entry not found.' });
  }
  res.json({ entry: entry });
});

// ==== WORLD-BUILDING: DELETE ====
app.delete('/api/world-entry/:id', (req, res) => {
  const email = req.query.email;
  const id = req.params.id;
  const existing = db.prepare('SELECT * FROM world_entries WHERE id = ? AND email = ?').get(id, email);
  if (!existing) {
    return res.status(404).json({ error: 'Entry not found.' });
  }
  db.prepare('DELETE FROM world_entries WHERE id = ?').run(id);
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
