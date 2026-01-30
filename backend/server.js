const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'changeme_admin_token';
const PORT = process.env.PORT || 8787;
const BASE_URL_ENV = process.env.BASE_URL;
const DEFAULT_RENDER_BASE = 'https://trendcurator.org';
// BASE_URL will be computed per-request in publish handler to avoid localhost in production
const BASE_URL = BASE_URL_ENV || `http://localhost:${PORT}`; // fallback for local dev
// DATA_DIR handling: prefer explicit env var; when on Render and DATA_DIR not set, default to Render-friendly workspace
const DEFAULT_RENDER_DATA_DIR = '/opt/render/project/src/backend/.data';
const DATA_DIR = process.env.DATA_DIR || (process.env.RENDER ? DEFAULT_RENDER_DATA_DIR : path.join(__dirname, '.data'));
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'data.sqlite');

// Ensure data dir exists; warn if using default ephemeral path
if(!process.env.DATA_DIR && process.env.RENDER){
  console.warn('WARNING: DATA_DIR not set; data may reset on redeploy. Recommend attaching a Render Persistent Disk and setting DATA_DIR=/var/data');
}
try{fs.mkdirSync(DATA_DIR, { recursive: true })}catch(e){console.error('Failed to create DATA_DIR', e)}

// Ensure db dir
try{fs.mkdirSync(path.dirname(DB_PATH), { recursive: true })}catch(e){console.error('Failed to create DB dir', e)}

console.log(JSON.stringify({ event: 'startup', dbPath: DB_PATH, dataDir: DATA_DIR }));

const db = new sqlite3.Database(DB_PATH);

// Init tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS subscribers (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    source TEXT,
    utm TEXT,
    ts INTEGER NOT NULL
  )`);

  // Stripe webhook events processed (idempotency)
  db.run(`CREATE TABLE IF NOT EXISTS stripe_events (
    id TEXT PRIMARY KEY,
    type TEXT,
    created INTEGER,
    received_ts INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS issues (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    reason TEXT NOT NULL,
    link TEXT,
    score INTEGER,
    ts INTEGER NOT NULL
  )`);

  // Links table for future georouting / safe redirects
  db.run(`CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    default_url TEXT NOT NULL,
    url_uk TEXT,
    url_us TEXT,
    url_eu TEXT,
    url_row TEXT,
    ts INTEGER NOT NULL
  )`);
});

const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      // tightened: only allow external scripts from self (we moved inline scripts to external files)
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      // allow inline styles for now; can be tightened later
      styleSrc: ["'self'", "https:", "'unsafe-inline'"],
      upgradeInsecureRequests: [],
    },
  },
}));
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

const signupLimiter = rateLimit({ windowMs: 60*1000, max: 10, message: {error: 'Too many signups from this IP, try again later'} });
app.use('/signup', signupLimiter);

// Validation schemas
const signupSchema = Joi.object({
  email: Joi.string().email().required(),
  source: Joi.string().max(200).allow('', null),
  utm: Joi.string().max(1000).allow('', null)
});

const publishSchema = Joi.object({
  title: Joi.string().max(300).required(),
  description: Joi.string().max(4000).required(),
  reason: Joi.string().max(2000).required(),
  link: Joi.string().uri().allow('', null),
  score: Joi.number().integer().min(0).max(100).optional()
});

// Routes
// Helper: send welcome email (Mailgun)
async function sendWelcomeEmail(toEmail){
  const MG_API_KEY = process.env.MAILGUN_API_KEY;
  const MG_DOMAIN = process.env.MAILGUN_DOMAIN;
  const FROM = process.env.EMAIL_FROM || `TrendCurator <welcome@${MG_DOMAIN || 'example.com'}>`;
  if(!MG_API_KEY || !MG_DOMAIN){
    console.warn('Mailgun not configured (MAILGUN_API_KEY or MAILGUN_DOMAIN missing). Signup will be accepted but no welcome email sent.');
    return { ok: false, reason: 'mailgun_not_configured' };
  }
  try{
    const url = `https://api.mailgun.net/v3/${MG_DOMAIN}/messages`;
    const params = new URLSearchParams();
    params.append('from', FROM);
    params.append('to', toEmail);
    params.append('subject', 'Welcome to TrendCurator — your first pick is coming');
    params.append('html', `<div style="font-family:Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f1113;line-height:1.4">
      <h2 style="margin:0 0 8px 0">Welcome — thanks for joining TrendCurator</h2>
      <p style="margin:0 0 12px 0;color:#555">Each week we send one short, human-curated product pick. No spam — unsubscribe any time.</p>
      <p style="margin:0 0 12px 0">If you didn't sign up, ignore this email.</p>
      <p style="margin:0">— TrendCurator</p>
    </div>`);

    const res = await fetch(url, { method: 'POST', headers: { 'Authorization': 'Basic ' + Buffer.from(`api:${MG_API_KEY}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, body: params });
    const text = await res.text();
    if(!res.ok){
      console.error('Mailgun send failed', res.status, text);
      return { ok: false, status: res.status, body: text };
    }
    console.log('Mailgun send success for', toEmail, text.substring(0,200));
    return { ok: true };
  }catch(e){
    console.error('Mailgun send exception', e);
    return { ok: false, reason: 'exception', error: e.message };
  }
}

app.post('/signup', async (req, res) => {
  const { error, value } = signupSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  const ts = Date.now();
  try{
    // check if email exists
    db.get('SELECT id FROM subscribers WHERE email = ?', [value.email], async (err,row)=>{
      if(err){ console.error('DB error', err); return res.status(500).json({ error: 'Database error' }); }
      if(row){
        // friendly response when already subscribed
        console.log(`[SIGNUP] existing email: ${value.email}`);
        // still attempt to send welcome if desired? skip to avoid duplicates
        return res.status(200).json({ ok: true, id: row.id, message: 'already_subscribed' });
      }
      const id = uuidv4();
      const stmt = db.prepare('INSERT INTO subscribers (id,email,source,utm,ts) VALUES (?,?,?,?,?)');
      stmt.run(id, value.email, value.source || null, value.utm || null, ts, async function(insertErr){
        if(insertErr){ console.error('DB error',insertErr); return res.status(500).json({ error: 'Database error' }); }
        console.log(`[SIGNUP] New signup: ${value.email} source=${value.source||''} utm=${value.utm||''}`);
        const resp = { ok: true, id };
        console.log(JSON.stringify({event:'signup', email: value.email, source: value.source||'', resp}));

        // Attempt to send welcome email, but do not block signup success if email provider missing or fails
        (async ()=>{
          const result = await sendWelcomeEmail(value.email).catch(e=>({ ok:false, reason:'exception', error:e.message }));
          if(result && result.ok){
            console.log(JSON.stringify({event:'welcome_email_sent', email: value.email}));
          } else {
            console.warn(JSON.stringify({event:'welcome_email_failed', email: value.email, detail: result}));
            // TODO: push to retry queue or mark in DB for retry
          }
        })();

        return res.json(resp);
      });
    });
  }catch(e){
    console.error('Signup exception', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/publish', (req, res) => {
  // Harden publish auth: require ADMIN_TOKEN env to be set and non-empty
  if (!process.env.ADMIN_TOKEN || process.env.ADMIN_TOKEN.trim() === '') {
    console.error('Publish attempt but ADMIN_TOKEN is not configured on server');
    return res.status(500).json({ error: 'Server misconfiguration: ADMIN_TOKEN not set' });
  }
  const token = req.header('x-admin-token') || req.query.admin_token || req.body.admin_token;
  if (!token || token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  const { error, value } = publishSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });

  const id = uuidv4();
  const ts = Date.now();

  // If a vendor link is provided, create a go/ slug entry and store the go link on the issue
  const createLinkAndIssue = (done) => {
    if(!value.link){
      // no external link provided — just insert issue with null link
      const stmt = db.prepare('INSERT INTO issues (id,title,description,reason,link,score,ts) VALUES (?,?,?,?,?,?,?)');
      stmt.run(id, value.title, value.description, value.reason, null, value.score||null, ts, (err)=> done(err, null));
      return;
    }
    // generate slug from title or url
    const baseSlug = (value.slug && String(value.slug).trim()) || String(value.title || '').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'') || uuidv4().slice(0,8);
    const trySlug = (candidate, cb) => {
      const lid = uuidv4();
      db.get('SELECT id FROM links WHERE slug = ?', [candidate], (err,row)=>{
        if(err) return cb(err);
        if(row) return cb(null, false); // exists
        // insert link record
        const lstmt = db.prepare('INSERT INTO links (id,slug,default_url,url_uk,url_us,url_eu,url_row,ts) VALUES (?,?,?,?,?,?,?,?)');
        lstmt.run(lid, candidate, value.link, null, null, null, null, ts, (lerr)=>{
          if(lerr) return cb(lerr);
          // compute public go link
          const baseUrl = BASE_URL_ENV || (process.env.RENDER ? DEFAULT_RENDER_BASE : `https://${process.env.HOSTNAME||'trendcurator.org'}`);
          const goUrl = `${baseUrl.replace(/\/$/,'')}/go/${candidate}`;
          // insert issue with goUrl
          const istmt = db.prepare('INSERT INTO issues (id,title,description,reason,link,score,ts) VALUES (?,?,?,?,?,?,?)');
          istmt.run(id, value.title, value.description, value.reason, goUrl, value.score||null, ts, (ierr)=> cb(ierr, { goUrl, slug: candidate }));
        });
      });
    };
    // attempt candidate and fallback if collision
    (function attempt(n){
      const candidate = n===0 ? baseSlug : `${baseSlug}-${Math.floor(Math.random()*9000)+1000}`;
      trySlug(candidate, (err, resInfo)=>{
        if(err) return done(err);
        if(resInfo===false) return attempt(n+1);
        return done(null, resInfo);
      });
    })(0);
  };

  createLinkAndIssue((err, resInfo)=>{
    if(err){ console.error('DB error',err); return res.status(500).json({ error: 'Database error' }); }
    db.get('SELECT COUNT(1) AS c FROM subscribers', (err2,row)=>{
      const count = (row && row.c) || 0;
      const baseUrl = BASE_URL_ENV || (process.env.RENDER ? DEFAULT_RENDER_BASE : `${req.get('x-forwarded-proto')||req.protocol}://${req.get('x-forwarded-host')||req.get('host')}`);
      const issueUrl = `${baseUrl.replace(/\/$/, '')}/archive.html#${id}`;
      console.log(JSON.stringify({event:'publish', id, title:value.title, subscribers:count, ts, baseUrl, issueUrl, linkInfo:resInfo||null}));
      return res.json({ ok: true, id, url: issueUrl, link: resInfo && resInfo.goUrl ? resInfo.goUrl : null });
    });
  });
});

app.get('/issues', (req, res) => {
  res.set('Cache-Control','no-store');
  db.all('SELECT id,title,description,reason,link,score,ts FROM issues ORDER BY ts DESC', (err,rows)=>{
    if(err) return res.status(500).json({ error: 'Database error' });
    return res.json(rows||[]);
  });
});

app.get('/issues/:id', (req, res) => {
  db.get('SELECT id,title,description,reason,link,score,ts FROM issues WHERE id=?', [req.params.id], (err,row)=>{
    if(err) return res.status(500).json({ error: 'Database error' });
    if(!row) return res.status(404).json({ error: 'Not found' });
    return res.json(row);
  });
});

// health
app.get('/health', (req,res)=>{
  res.json({ ok:true, ts: Date.now() });
});

// Redirect handler for go/:slug
app.get('/go/:slug', (req, res) => {
  const slug = req.params.slug;
  if(!slug) return res.redirect(302, '/');
  db.get('SELECT default_url,url_uk,url_us,url_eu,url_row FROM links WHERE slug = ?', [slug], (err,row)=>{
    if(err){ console.error('DB error on redirect', err); return res.redirect(302, '/'); }
    if(!row) return res.status(404).send('Not found');
    // For now, always use default_url. Later: use Cloudflare country header to choose.
    const dest = row.default_url;
    if(!dest) return res.redirect(302, '/');
    return res.redirect(302, dest);
  });
});

// Stripe scaffold: create checkout session, webhook, billing portal
const STRIPE_SECRET = process.env.STRIPE_SECRET;
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID; // price for Pro
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

app.post('/create-checkout-session', async (req, res) => {
  if (!STRIPE_SECRET || !STRIPE_PRICE_ID) {
    return res.status(501).json({ error: 'Stripe not configured (STRIPE_SECRET or STRIPE_PRICE_ID missing)' });
  }
  // minimal validation
  const { success_url, cancel_url, customer_email, plan } = req.body || {};
  if (!success_url || !cancel_url) {
    return res.status(400).json({ error: 'success_url and cancel_url are required in body' });
  }
  try {
    const body = req.body || {};
    // Minimal payload: { success_url, cancel_url, customer_email, plan }
    const success_url = body.success_url || (BASE_URL.replace(/\/$/,'') + '/');
    const cancel_url = body.cancel_url || (BASE_URL.replace(/\/$/,'') + '/');
    const customer_email = (body.customer_email || null);
    const normalizedEmail = customer_email ? String(customer_email).trim().toLowerCase() : null;

    // choose price id by plan (default to monthly)
    const planChoice = (String(body.plan || 'monthly')).toLowerCase();
    const monthly = process.env.STRIPE_PRICE_ID_MONTHLY || STRIPE_PRICE_ID;
    const yearly = process.env.STRIPE_PRICE_ID_YEARLY || null;
    let chosenPriceId = monthly;
    if(planChoice === 'yearly'){
      if(!yearly) return res.status(500).json({ error: 'Yearly price id not configured (STRIPE_PRICE_ID_YEARLY)' });
      chosenPriceId = yearly;
    }

    // Lazy require to avoid crash when stripe not installed
    const Stripe = require('stripe');
    const stripe = Stripe(STRIPE_SECRET);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: chosenPriceId, quantity: 1 }],
      success_url,
      cancel_url,
      customer_email: normalizedEmail,
      client_reference_id: normalizedEmail || undefined,
      metadata: normalizedEmail ? { subscriber_email: normalizedEmail, plan: planChoice } : { plan: planChoice }
    });
    return res.json({ ok: true, url: session.url, id: session.id, plan: planChoice });
  } catch (e) {
    console.error('Stripe create-checkout error', e);
    return res.status(500).json({ error: 'Stripe error', detail: e.message });
  }
});

// webhook endpoint
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!STRIPE_SECRET || !STRIPE_WEBHOOK_SECRET) {
    res.status(501).json({ error: 'Stripe webhook not configured' });
    return;
  }
  const payload = req.body;
  const sig = req.headers['stripe-signature'];
  const Stripe = require('stripe');
  const stripe = Stripe(STRIPE_SECRET);
  let event;
  try {
    event = stripe.webhooks.constructEvent(payload, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Idempotency: record event.id to avoid double-processing
  try{
    const evId = event.id;
    const evCreated = event.created || Math.floor(Date.now()/1000);
    db.run('INSERT INTO stripe_events (id,type,created,received_ts) VALUES (?,?,?,?)', [evId, event.type, evCreated, Date.now()], (err)=>{
      if(err){
        console.log('Stripe webhook dedup: event already processed', evId);
        return res.json({ ok:true, deduped:true });
      }
      // continue to switch below
      
  switch (event.type) {
    case 'checkout.session.completed':
      console.log('stripe event: checkout.session.completed', event.data.object.id);
      break;
    case 'invoice.payment_succeeded':
      console.log('stripe event: invoice.payment_succeeded', event.data.object.id);
      break;
    case 'customer.subscription.updated':
      console.log('stripe event: customer.subscription.updated', event.data.object.id);
      break;
    default:
      console.log(`Unhandled Stripe event type: ${event.type}`);
  }
  res.json({ received: true });
});

// Billing portal redirect (create session)
app.get('/billing-portal', async (req, res) => {
  if (!STRIPE_SECRET) {
    return res.status(501).json({ error: 'Stripe not configured' });
  }
  const customer_id = req.query.customer_id;
  if (!customer_id) return res.status(400).json({ error: 'customer_id required' });
  try {
    const Stripe = require('stripe');
    const stripe = Stripe(STRIPE_SECRET);
    const session = await stripe.billingPortal.sessions.create({ customer: customer_id, return_url: BASE_URL.replace(/\/$/,'/') });
    return res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error('Stripe billing-portal error', e);
    return res.status(500).json({ error: 'Stripe error', detail: e.message });
  }
});


// simple structured logging middleware for analytics
app.use((req,res,next)=>{
  const start = Date.now();
  res.on('finish', ()=>{
    const entry = { event:'request', method:req.method, path:req.path, status:res.statusCode, ip:req.ip, ua:req.headers['user-agent'], duration: Date.now()-start };
    console.log(JSON.stringify(entry));
  });
  next();
});


// Serve preview site static (optional)
// To avoid accidental response concatenation at the edge, explicitly serve index.html for '/'
app.get('/', (req, res, next) => {
  try{
    const indexPath = path.join(__dirname, '..', 'web-preview', 'index.html');
    const content = fs.readFileSync(indexPath, 'utf8');
    res.set('Content-Type', 'text/html; charset=utf-8');
    // add a diagnostic header so we can see which service served the page
    res.set('X-Served-By', 'trendcurator-backend');
    return res.send(content);
  }catch(e){
    console.error('Failed to read index.html', e);
    return next();
  }
});

// Serve other static assets
app.use('/', express.static(path.join(__dirname, '..', 'web-preview')));

app.listen(PORT, '0.0.0.0', ()=>{
  console.log(`TrendCurator backend listening on http://0.0.0.0:${PORT}`);
});
