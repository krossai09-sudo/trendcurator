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
    ts INTEGER NOT NULL,
    pro INTEGER DEFAULT 0,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    stripe_status TEXT,
    current_period_end INTEGER,
    stripe_updated_ts INTEGER
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
    affiliate_url TEXT,
    url_uk TEXT,
    url_us TEXT,
    url_eu TEXT,
    url_row TEXT,
    ts INTEGER NOT NULL
  )`);

  // clicks table for tracking redirects
  db.run(`CREATE TABLE IF NOT EXISTS clicks (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    ts INTEGER NOT NULL,
    ip TEXT,
    ua TEXT,
    country TEXT
  )`);

  // Stripe webhook events processed (idempotency)
  db.run(`CREATE TABLE IF NOT EXISTS stripe_events (
    id TEXT PRIMARY KEY,
    type TEXT,
    created INTEGER,
    received_ts INTEGER
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
// Outgoing emails queue table
// Fields: id, to_email, subject, body_html, attempts, last_error, status, ts_created, ts_sent

// enqueue email helper
function enqueueEmail(to_email, subject, body_html){
  const eid = uuidv4();
  const ts = Date.now();
  const stmt = db.prepare('INSERT INTO outgoing_emails (id,to_email,subject,body_html,attempts,last_error,status,ts_created,ts_sent) VALUES (?,?,?,?,?,?,?,?,?)');
  stmt.run(eid, to_email, subject, body_html, 0, null, 'queued', ts, null, (err)=>{
    if(err) console.error('Failed to enqueue email', err);
  });
  return eid;
}

// Worker: attempt to send an email via Resend (HTTP API)
async function attemptSendEmail(emailRow){
  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  const FROM = process.env.EMAIL_FROM || `TrendCurator <no-reply@trendcurator.org>`;
  if(!RESEND_API_KEY){
    throw new Error('Resend API key not configured');
  }
  const payload = { from: FROM, to: [emailRow.to_email], subject: emailRow.subject, html: emailRow.body_html };
  const res = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  const text = await res.text();
  if(!res.ok){
    const err = new Error('Resend send failed: ' + res.status + ' ' + text);
    err.status = res.status; err.body = text;
    throw err;
  }
  return JSON.parse(text || '{}');
}

// Worker runner (called periodically or via admin endpoint)
async function processEmailQueue(limit=10){
  return new Promise((resolve)=>{
    db.all("SELECT id,to_email,subject,body_html,attempts,last_error FROM outgoing_emails WHERE status IN ('queued','failed') ORDER BY ts_created ASC LIMIT ?", [limit], async (err, rows)=>{
      if(err || !rows) return resolve({ ok:false, error: err ? err.message : 'no rows' });
      const results = [];
      for(const r of rows){
        try{
          // exponential backoff: skip retries where attempts >0 and last attempt was recent
          if(r.attempts>0){
            // simple backoff: wait attempts^2 * 1000 ms since last error (not storing last attempt time for simplicity)
          }
          await attemptSendEmail(r);
          const tsent = Date.now();
          db.run('UPDATE outgoing_emails SET status=?,attempts=attempts+1,ts_sent=?,last_error=NULL WHERE id=?', ['sent', tsent, r.id]);
          results.push({ id: r.id, status: 'sent' });
        }catch(e){
          console.error('Email send attempt failed for', r.id, e.message || e);
          const attempts = (r.attempts || 0) + 1;
          const last_error = (e.message||String(e)).slice(0,1000);
          const status = attempts >= 5 ? 'permanent_failed' : 'failed';
          db.run('UPDATE outgoing_emails SET status=?,attempts=?,last_error=? WHERE id=?', [status, attempts, last_error, r.id]);
          results.push({ id: r.id, status });
        }
      }
      resolve({ ok:true, results });
    });
  });
}

// Admin endpoints for queue inspection
app.get('/admin/api/email-queue', checkAdmin, (req,res)=>{
  db.all('SELECT id,to_email,subject,attempts,last_error,status,ts_created,ts_sent FROM outgoing_emails ORDER BY ts_created DESC LIMIT 200', (err,rows)=>{
    if(err) return res.status(500).json({ error: 'Database error' });
    return res.json(rows||[]);
  });
});

app.post('/admin/api/email-queue/process', checkAdmin, async (req,res)=>{
  const result = await processEmailQueue(20);
  return res.json(result);
});

app.post('/admin/api/email-queue/:id/retry', checkAdmin, (req,res)=>{
  const id = req.params.id;
  db.run('UPDATE outgoing_emails SET status=?,attempts=? WHERE id=?', ['queued', 0, id], function(err){
    if(err) return res.status(500).json({ error: 'Database error' });
    return res.json({ ok:true, id });
  });
});

// Helper: send welcome email (enqueue for Resend)
function sendWelcomeEmail(toEmail){
  const FROM = process.env.EMAIL_FROM || `TrendCurator <no-reply@trendcurator.org>`;
  const subject = 'Welcome to TrendCurator — your first pick is coming';
  const body = `<div style="font-family:Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f1113;line-height:1.4">
      <h2 style="margin:0 0 8px 0">Welcome — thanks for joining TrendCurator</h2>
      <p style="margin:0 0 12px 0;color:#555">Each week we send one short, human-curated product pick. No spam — unsubscribe any time.</p>
      <p style="margin:0 0 12px 0">If you didn't sign up, ignore this email.</p>
      <p style="margin:0">— TrendCurator</p>
    </div>`;
  // enqueue and return id
  enqueueEmail(toEmail, subject, body);
  return { ok:true };
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
        return res.status(200).json({ ok: true, id: row.id, message: 'already_subscribed' });
      }
      const id = uuidv4();
      const stmt = db.prepare('INSERT INTO subscribers (id,email,source,utm,ts) VALUES (?,?,?,?,?)');
      stmt.run(id, value.email, value.source || null, value.utm || null, ts, async function(insertErr){
        if(insertErr){ console.error('DB error',insertErr); return res.status(500).json({ error: 'Database error' }); }
        console.log(`[SIGNUP] New signup: ${value.email} source=${value.source||''} utm=${value.utm||''}`);
        const resp = { ok: true, id };
        console.log(JSON.stringify({event:'signup', email: value.email, source: value.source||'', resp}));

        // Enqueue welcome email (non-blocking)
        try{
          sendWelcomeEmail(value.email);
          console.log('Enqueued welcome email for', value.email);
        }catch(e){ console.error('Failed to enqueue welcome email', e); }

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
        const lstmt = db.prepare('INSERT INTO links (id,slug,default_url,affiliate_url,url_uk,url_us,url_eu,url_row,ts) VALUES (?,?,?,?,?,?,?,?,?)');
        lstmt.run(lid, candidate, value.link, (value.affiliate_url || null), null, null, null, null, ts, (lerr)=>{
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
    // Prefer affiliate_url when present, fallback to default_url
    const dest = row.affiliate_url || row.default_url;
    if(!dest) return res.redirect(302, '/');
    // Log click (async, non-blocking)
    (async ()=>{
      try{
        const cid = uuidv4();
        const ts = Date.now();
        const ip = req.get('cf-connecting-ip') || req.get('x-forwarded-for') || req.ip || null;
        const ua = req.get('user-agent') || null;
        const country = req.get('cf-ipcountry') || req.get('x-country') || null;
        db.run('INSERT INTO clicks (id,link_id,slug,ts,ip,ua,country) VALUES (?,?,?,?,?,?,?)', [cid, row.id, slug, ts, ip, ua, country], ()=>{});
      }catch(e){ console.error('Failed to log click', e); }
    })();
    return res.redirect(302, dest);
  });
});

// Admin API: protected by X-Admin-Token header (must match ADMIN_TOKEN)
function checkAdmin(req,res,next){
  const token = req.header('x-admin-token') || req.query.admin_token || req.body.admin_token;
  if(!process.env.ADMIN_TOKEN || process.env.ADMIN_TOKEN.trim()==='') return res.status(500).json({ error: 'Server misconfiguration: ADMIN_TOKEN not set' });
  if(!token || token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  return next();
}

// List links with referencing issues
app.get('/admin/api/links', checkAdmin, (req,res)=>{
  db.all('SELECT id,slug,default_url,url_uk,url_us,url_eu,url_row,ts FROM links ORDER BY ts DESC', (err,rows)=>{
    if(err) return res.status(500).json({ error: 'Database error' });
    if(!rows) rows = [];
    // for each link, find referencing issues
    const tasks = rows.map(r=>new Promise((resolve)=>{
      db.all('SELECT id,title FROM issues WHERE link = ?', [ `${BASE_URL_ENV || (process.env.RENDER ? DEFAULT_RENDER_BASE : 'https://trendcurator.org')}/go/` + r.slug ], (e,issues)=>{
        if(e) return resolve(Object.assign({}, r, { issues: [] }));
        return resolve(Object.assign({}, r, { issues: issues || [] }));
      });
    }));
    Promise.all(tasks).then(results=>res.json(results)).catch(()=>res.status(500).json({ error: 'Database error' }));
  });
});

// Admin: get recent clicks for a slug
app.get('/admin/api/links/:slug/clicks', checkAdmin, (req,res)=>{
  const slug = req.params.slug;
  db.all('SELECT id,ts,ip,ua,country FROM clicks WHERE slug = ? ORDER BY ts DESC LIMIT 200', [slug], (err,rows)=>{
    if(err) return res.status(500).json({ error: 'Database error' });
    return res.json(rows||[]);
  });
});

app.post('/admin/api/links', checkAdmin, express.json(), (req,res)=>{
  const { slug, default_url, url_uk, url_us, url_eu, url_row } = req.body || {};
  if(!slug || !default_url) return res.status(400).json({ error: 'slug and default_url required' });
  const id = uuidv4(); const ts = Date.now();
  db.run('INSERT INTO links (id,slug,default_url,url_uk,url_us,url_eu,url_row,ts) VALUES (?,?,?,?,?,?,?,?)', [id,slug,default_url,url_uk||null,url_us||null,url_eu||null,url_row||null,ts], function(err){
    if(err) return res.status(500).json({ error: 'Database error', detail: err.message });
    return res.json({ ok:true, id, slug, go: `${BASE_URL_ENV || (process.env.RENDER ? DEFAULT_RENDER_BASE : 'https://trendcurator.org')}/go/${slug}` });
  });
});

app.put('/admin/api/links/:slug', checkAdmin, express.json(), (req,res)=>{
  const slug = req.params.slug;
  const { default_url, url_uk, url_us, url_eu, url_row } = req.body || {};
  db.run('UPDATE links SET default_url=?,url_uk=?,url_us=?,url_eu=?,url_row=? WHERE slug=?', [default_url||null,url_uk||null,url_us||null,url_eu||null,url_row||null,slug], function(err){
    if(err) return res.status(500).json({ error: 'Database error', detail: err.message });
    return res.json({ ok:true, slug });
  });
});

app.delete('/admin/api/links/:slug', checkAdmin, (req,res)=>{
  const slug = req.params.slug;
  db.run('DELETE FROM links WHERE slug = ?', [slug], function(err){
    if(err) return res.status(500).json({ error: 'Database error' });
    return res.json({ ok:true, slug });
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
  const { success_url, cancel_url, customer_email } = req.body || {};
  if (!success_url || !cancel_url) {
    return res.status(400).json({ error: 'success_url and cancel_url are required in body' });
  }
  try {
    const body = req.body || {};
    // Minimal payload: { success_url, cancel_url, customer_email }
    const success_url = body.success_url || (BASE_URL.replace(/\/$/,'') + '/');
    const cancel_url = body.cancel_url || (BASE_URL.replace(/\/$/,'') + '/');
    const customer_email = body.customer_email || null;
    // Lazy require to avoid crash when stripe not installed
    const Stripe = require('stripe');
    const stripe = Stripe(STRIPE_SECRET);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      success_url,
      cancel_url,
      customer_email,
    });
    return res.json({ ok: true, url: session.url, id: session.id });
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

  const obj = event.data && event.data.object;

  // Idempotency: record event.id to avoid double-processing
  try{
    const evId = event.id;
    const evCreated = event.created || Math.floor(Date.now()/1000);
    db.run('INSERT INTO stripe_events (id,type,created,received_ts) VALUES (?,?,?,?)', [evId, event.type, evCreated, Date.now()], (err)=>{
      if(err){
        // unique constraint -> already processed
        console.log('Stripe webhook dedup: event already processed', event.id);
        return res.json({ ok:true, deduped:true });
      }
      // continue processing below
      (async ()=>{
        try{
          switch(event.type){
        case 'checkout.session.completed':{
          const session = obj;
          const email = (session.customer_details && session.customer_details.email) || session.customer_email || null;
          const customerId = session.customer || null;
          const subscriptionId = session.subscription || null; // may be present
          console.log('stripe webhook: checkout.session.completed for', email, 'customer', customerId, 'subscription', subscriptionId);

          const now = Date.now();
          const updateSubscriber = (id)=>{
            db.run('UPDATE subscribers SET pro=1,stripe_customer_id=?,stripe_subscription_id=?,stripe_updated_ts=? WHERE id=?', [customerId, subscriptionId, now, id]);
          };
          const insertSubscriber = (emailToUse)=>{
            const sid = uuidv4();
            db.run('INSERT INTO subscribers (id,email,ts,pro,stripe_customer_id,stripe_subscription_id,stripe_updated_ts) VALUES (?,?,?,?,?,?,?)', [sid,emailToUse,now,1,customerId,subscriptionId,now]);
          };

          if(email){
            // prefer matching by email
            db.get('SELECT id FROM subscribers WHERE email = ?', [email], async (err,row)=>{
              if(err) return console.error('DB error updating subscriber on checkout', err);
              if(row){
                updateSubscriber(row.id);
              } else {
                insertSubscriber(email);
              }

              // if subscriptionId is present, fetch subscription details to populate status/period
              try{
                if(subscriptionId){
                  const Stripe = require('stripe'); const stripe = Stripe(STRIPE_SECRET);
                  const sub = await stripe.subscriptions.retrieve(subscriptionId);
                  const status = sub.status; const current_period_end = sub.current_period_end ? sub.current_period_end * 1000 : null;
                  db.run('UPDATE subscribers SET stripe_subscription_id=?,stripe_status=?,current_period_end=?,stripe_updated_ts=? WHERE email=?', [subscriptionId, status, current_period_end, Date.now(), email]);
                }
              }catch(e){ console.error('Failed to fetch subscription after checkout', e); }
            });
          } else if(customerId){
            // no email on session; try to match by customer id
            db.get('SELECT id,email FROM subscribers WHERE stripe_customer_id = ?', [customerId], async (err,row)=>{
              if(err) return console.error('DB error updating subscriber on checkout (by customer)', err);
              if(row){ updateSubscriber(row.id); }
              else { /* no subscriber to update */ }
              if(subscriptionId){
                try{ const Stripe = require('stripe'); const stripe = Stripe(STRIPE_SECRET); const sub = await stripe.subscriptions.retrieve(subscriptionId); const status = sub.status; const current_period_end = sub.current_period_end ? sub.current_period_end * 1000 : null; db.run('UPDATE subscribers SET stripe_subscription_id=?,stripe_status=?,current_period_end=?,stripe_updated_ts=? WHERE stripe_customer_id=?', [subscriptionId, status, current_period_end, Date.now(), customerId]); }catch(e){ console.error('Failed to fetch subscription after checkout (customerId path)', e); }
              }
            });
          }
          break;
        }
        case 'customer.subscription.created':
        case 'customer.subscription.updated':{
          const sub = obj;
          const customerId = sub.customer;
          const subId = sub.id;
          const status = sub.status;
          const current_period_end = sub.current_period_end ? sub.current_period_end * 1000 : null;
          const now = Date.now();
          console.log('stripe webhook: subscription event', subId, status);
          // Update subscribers by customer id
          db.get('SELECT id FROM subscribers WHERE stripe_customer_id = ?', [customerId], (err,row)=>{
            if(err) return console.error('DB error on sub update', err);
            if(row){
              db.run('UPDATE subscribers SET pro=?,stripe_subscription_id=?,stripe_status=?,current_period_end=?,stripe_updated_ts=? WHERE id=?', [ (status==='active'?1:0), subId, status, current_period_end, now, row.id ]);
            } else {
              // no subscriber found — try to match by email inside sub if present
              const email = (sub && sub.customer_email) || null;
              if(email){
                db.get('SELECT id FROM subscribers WHERE email = ?', [email], (e2,r2)=>{
                  if(e2) return console.error('DB error on sub update email match', e2);
                  if(r2){ db.run('UPDATE subscribers SET pro=?,stripe_customer_id=?,stripe_subscription_id=?,stripe_status=?,current_period_end=?,stripe_updated_ts=? WHERE id=?', [ (status==='active'?1:0), customerId, subId, status, current_period_end, now, r2.id ]); }
                });
              }
            }
          });
          break;
        }
        case 'customer.subscription.deleted':{
          const sub = obj; const customerId = sub.customer; const subId = sub.id; const status = sub.status || 'canceled'; const now = Date.now();
          db.get('SELECT id,current_period_end FROM subscribers WHERE stripe_subscription_id = ?', [subId], (err,row)=>{
            if(err) return console.error('DB error on sub deleted', err);
            if(row){
              // If current_period_end present, keep pro until period end; otherwise clear immediately
              if(row.current_period_end && row.current_period_end > Date.now()){
                db.run('UPDATE subscribers SET stripe_status=?,stripe_updated_ts=? WHERE id=?', [status, now, row.id]);
              } else {
                db.run('UPDATE subscribers SET pro=0,stripe_status=?,stripe_updated_ts=? WHERE id=?', [status, now, row.id]);
              }
            }
          });
          break;
        }
        case 'invoice.payment_failed':{
          const inv = obj; const customerId = inv.customer; const now = Date.now();
          db.get('SELECT id FROM subscribers WHERE stripe_customer_id = ?', [customerId], (err,row)=>{
            if(err) return console.error('DB error on invoice failed', err);
            if(row){ db.run('UPDATE subscribers SET stripe_status=?,stripe_updated_ts=? WHERE id=?', ['past_due', now, row.id]); }
          });
          break;
        }
        default:
          console.log('Unhandled Stripe event type:', event.type);
      }
    }catch(e){ console.error('Error processing webhook', e); }
  })();

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

  // Optional in-process email worker controlled by env var EMAIL_WORKER
  const EMAIL_WORKER = process.env.EMAIL_WORKER === '1' || process.env.EMAIL_WORKER === 'true';
  if(EMAIL_WORKER){
    console.log('Starting in-process email worker (every 60s)');
    let workerRunning = false;
    const tick = async ()=>{
      if(workerRunning) return; // simple lock
      workerRunning = true;
      try{
        const res = await processEmailQueue(25);
        if(res && res.ok){ console.log('Email worker processed', res.results.length, 'items'); }
        else { console.warn('Email worker error', res); }
      }catch(e){ console.error('Email worker exception', e); }
      workerRunning = false;
    };
    // initial tick after short delay to allow startup
    setTimeout(()=>{ tick(); setInterval(tick, 60*1000); }, 5000);
  }
});
