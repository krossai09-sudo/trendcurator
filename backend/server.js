const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
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

// Run lightweight migrations: add new columns and tables only when missing
db.serialize(()=>{
  const ensureColumn = (table, column, def) => {
    db.all(`PRAGMA table_info(${table})`, (err, cols) => {
      if(err || !cols) return;
      const names = cols.map(c=>c.name);
      if(!names.includes(column)){
        console.log(`Migrating: adding column ${column} to ${table}`);
        db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`,(a,b)=>{});
      }
    });
  };

  // subscribers: add tier and stripe fields
  ensureColumn('subscribers','tier',"TEXT NOT NULL DEFAULT 'free'");
  ensureColumn('subscribers','stripe_customer_id','TEXT');
  ensureColumn('subscribers','stripe_subscription_id','TEXT');
  ensureColumn('subscribers','stripe_status','TEXT');
  ensureColumn('subscribers','current_period_end','INTEGER');
  ensureColumn('subscribers','last_email_sent_ts','INTEGER');

  // issues: add visibility/type/published_for_month
  ensureColumn('issues','visibility',"TEXT NOT NULL DEFAULT 'pro'");
  ensureColumn('issues','type',"TEXT NOT NULL DEFAULT 'monthly_pro'");
  ensureColumn('issues','published_for_month','TEXT');

  // create email_queue if missing
  db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='email_queue'", (err,row)=>{
    if(err) return console.error('Migration check error',err);
    if(!row){
      console.log('Creating table email_queue');
      db.run(`CREATE TABLE email_queue (
        id TEXT PRIMARY KEY,
        subscriber_id TEXT,
        issue_id TEXT,
        template TEXT,
        status TEXT DEFAULT 'pending',
        attempts INTEGER DEFAULT 0,
        ts INTEGER NOT NULL
      )`);
    }
  });
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
app.use(cookieParser());
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
// sendWelcomeEmail placeholder — we enqueue welcome emails into email_queue and use Resend via worker
async function sendWelcomeEmail(toEmail){
  // legacy stub — we now enqueue welcome emails to email_queue and process them via /_worker/process-email
  console.log(JSON.stringify({ event:'email_enqueue_request', email: toEmail }));
  return { ok:true };
}

app.post('/signup', async (req, res) => {
  const { error, value } = signupSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  // normalize email to avoid case/whitespace duplicates
  value.email = String(value.email).trim().toLowerCase();
  const ts = Date.now();
  try{
    // check if email exists
    db.get('SELECT id,tier FROM subscribers WHERE email = ?', [value.email], async (err,row)=>{
      if(err){ console.error('DB error', err); return res.status(500).json({ error: 'Database error' }); }
      if(row){
        // friendly response when already subscribed
        console.log(`[SIGNUP] existing email: ${value.email}`);
        return res.status(200).json({ ok: true, id: row.id, message: 'already_subscribed' });
      }
      const id = uuidv4();
      const stmt = db.prepare('INSERT INTO subscribers (id,email,source,utm,ts,tier) VALUES (?,?,?,?,?,?)');
      stmt.run(id, value.email, value.source || null, value.utm || null, ts, 'free', async function(insertErr){
        if(insertErr){ console.error('DB error',insertErr); return res.status(500).json({ error: 'Database error' }); }
        console.log(`[SIGNUP] New signup: ${value.email} source=${value.source||''} utm=${value.utm||''}`);
        const resp = { ok: true, id };
        console.log(JSON.stringify({event:'signup', email: value.email, source: value.source||'', resp}));

        // Enqueue welcome email (uses template welcome_free)
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='email_queue'", (errq,rq)=>{
          if(errq || !rq){ console.warn('email_queue not present, skipping welcome enqueue'); return; }
          const insert = db.prepare('INSERT INTO email_queue (id,subscriber_id,issue_id,template,status,attempts,ts) VALUES (?,?,?,?,?,?,?)');
          try{ insert.run(uuidv4(), id, null, 'welcome_free', 'pending', 0, Date.now()); insert.finalize(()=>{ console.log('Enqueued welcome_free for', id); }); }
          catch(e){ console.error('enqueue welcome failed', e); }
        });

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
      console.log(JSON.stringify({event:'publish_issue', id, title:value.title, subscribers:count, ts, baseUrl, issueUrl, linkInfo:resInfo||null}));

      // Enqueue emails for matching subscribers if email_queue exists
      db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='email_queue'", (errq,rq)=>{
        if(errq || !rq){ console.warn('email_queue not present, skipping enqueue'); return res.json({ ok: true, id, url: issueUrl, link: resInfo && resInfo.goUrl ? resInfo.goUrl : null }); }
        // Determine recipients based on issue visibility (fall back to 'pro')
        const visibility = value.visibility || 'pro';
        const templ = (visibility==='free') ? 'free_pick' : (value.type==='weekly_pro' ? 'pro_weekly' : 'pro_monthly');
        const tierFilter = (visibility==='free') ? "tier='free'" : "tier='pro'";
        db.all(`SELECT id,email FROM subscribers WHERE ${tierFilter}`, (se, subs)=>{
          if(se || !subs || !subs.length){ console.log('No subscribers matched for enqueue', se); return res.json({ ok: true, id, url: issueUrl, link: resInfo && resInfo.goUrl ? resInfo.goUrl : null }); }
          const tsNow = Date.now();
          const insert = db.prepare('INSERT INTO email_queue (id,subscriber_id,issue_id,template,status,attempts,ts) VALUES (?,?,?,?,?,?,?)');
          let enqueued = 0;
          subs.forEach(s=>{
            try{ insert.run(uuidv4(), s.id, id, templ, 'pending', 0, tsNow); enqueued++; }catch(ie){ /* ignore */ }
          });
          insert.finalize(()=>{ console.log(`Enqueued ${enqueued} emails for issue ${id} template=${templ}`); return res.json({ ok: true, id, url: issueUrl, link: resInfo && resInfo.goUrl ? resInfo.goUrl : null, enqueued }); });
        });
      });
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
  // Support monthly/yearly via STRIPE_PRICE_ID_MONTHLY / STRIPE_PRICE_ID_YEARLY
  const PRICE_MONTHLY = process.env.STRIPE_PRICE_ID_MONTHLY || process.env.STRIPE_PRICE_ID;
  const PRICE_YEARLY = process.env.STRIPE_PRICE_ID_YEARLY || process.env.STRIPE_PRICE_ID;
  if (!STRIPE_SECRET || (!PRICE_MONTHLY && !PRICE_YEARLY)) {
    return res.status(501).json({ error: 'Stripe not configured (STRIPE_SECRET or STRIPE_PRICE_ID missing)' });
  }
  // minimal validation
  const body = req.body || {};
  const b_success = body.success_url;
  const b_cancel = body.cancel_url;
  if (!b_success || !b_cancel) {
    return res.status(400).json({ error: 'success_url and cancel_url are required in body' });
  }
  try {
    const success_url = b_success || (BASE_URL.replace(/\/$/,'') + '/');
    const cancel_url = b_cancel || (BASE_URL.replace(/\/$/,'') + '/');
    const customer_email = body.customer_email || null;
    const plan = (body.plan || 'monthly').toLowerCase();
    let priceToUse = PRICE_MONTHLY;
    if(plan === 'yearly') priceToUse = PRICE_YEARLY;
    if(!priceToUse) return res.status(501).json({ error: 'Stripe price IDs not configured for selected plan' });

    // Lazy require to avoid crash when stripe not installed
    const Stripe = require('stripe');
    const stripe = Stripe(STRIPE_SECRET);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceToUse, quantity: 1 }],
      success_url,
      cancel_url,
      customer_email,
    });
    console.log(JSON.stringify({ event: 'checkout_session_created', id: session.id, price: priceToUse, customer_email: customer_email || null }));
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
  // Handle event types
  try{
    const obj = event.data.object || {};
    switch (event.type) {
      case 'checkout.session.completed':
        console.log('stripe event: checkout.session.completed', obj.id);
        (async ()=>{
          try{
            const email = obj.customer_email || (obj.customer && obj.customer.email) || null;
            const customer = obj.customer || obj.customer_id || null;
            const subscription_id = obj.subscription || null;
            const seid = uuidv4();
            db.run('INSERT INTO links (id,slug,default_url,ts) VALUES (?,?,?,?)', [seid, `evt-${seid}`, `stripe:${obj.id}`, Date.now()], ()=>{});
            if(email){
              db.get('SELECT id,pro FROM subscribers WHERE email = ?', [email], (err,row)=>{
                if(err) return console.error('DB error matching email',err);
                const sid = row ? row.id : uuidv4();
                const nowTs = Date.now();
                const updateOrInsert = row ?
                  db.run('UPDATE subscribers SET pro=1, stripe_customer_id=?, stripe_subscription_id=?, stripe_status=?, current_period_end=?, stripe_updated_ts=? WHERE id=?', [customer, subscription_id, 'active', null, nowTs, sid], (uerr)=>{
                    if(uerr) console.error('DB update error', uerr); else console.log(JSON.stringify({ event:'pro_granted', email, subscription_id }));
                  })
                :
                  db.run('INSERT INTO subscribers (id,email,source,utm,ts,pro,stripe_customer_id,stripe_subscription_id,stripe_status,current_period_end,stripe_updated_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)', [sid,email,'stripe',null,nowTs,1,customer,subscription_id,'active',null,nowTs], (ierr)=>{
                    if(ierr) console.error('DB insert error', ierr); else console.log(JSON.stringify({ event:'pro_granted', email, subscription_id }));
                  });
              });
            }
          }catch(e){ console.error('checkout.session.process error', e); }
        })();
        break;
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
        console.log('stripe event: subscription', obj.id);
        // persist subscription info and mark subscriber pro if active
        (async ()=>{
          try{
            const customerId = obj.customer;
            const status = obj.status;
            const current_period_end = obj.current_period_end ? obj.current_period_end*1000 : null;
            // find subscriber by stripe_customer_id or email
            db.get('SELECT id,email FROM subscribers WHERE stripe_customer_id = ? OR email = ?', [customerId, (obj.customer_email||null)], (err,row)=>{
              if(err) return console.error('DB error',err);
              if(row){
                const sid = row.id;
                db.run('UPDATE subscribers SET stripe_customer_id=?, stripe_subscription_id=?, stripe_status=?, current_period_end=?, tier=? WHERE id=?', [customerId, obj.id, status, current_period_end, (status==='active' || status==='trialing' || (current_period_end && current_period_end>Date.now())) ? 'pro' : 'free', sid]);
                console.log('Updated subscriber subscription state', sid, status);
              } else {
                console.log('No matching subscriber for subscription event', customerId);
              }
            });
          }catch(e){ console.error('subscription.process error', e); }
        })();
        break;
      case 'invoice.payment_succeeded':
        console.log('stripe event: invoice.payment_succeeded', obj.id);
        break;
      default:
        console.log(`Unhandled Stripe event type: ${event.type}`);
    }
  }catch(e){ console.error('Error handling stripe event', e); }
  res.json({ received: true });
});

// Simple email worker endpoint (process pending emails). Use RESEND_API_KEY to actually send.
app.post('/_worker/process-email', async (req,res)=>{
  const limit = parseInt(req.query.limit||'10',10);
  db.all("SELECT id,subscriber_id,issue_id,template,ts FROM email_queue WHERE status='pending' ORDER BY ts ASC LIMIT ?", [limit], async (err, rows)=>{
    if(err) return res.status(500).json({ error:'db' });
    if(!rows || !rows.length) return res.json({ ok:true, processed:0 });
    const RESEND_KEY = process.env.RESEND_API_KEY;
    const FROM = process.env.RESEND_FROM || 'no-reply@trendcurator.org';
    let processed = 0;
    for(const r of rows){
      // start processing row
      console.log(JSON.stringify({ event:'email_worker_process_start', id: r.id, template: r.template }));
      // fetch subscriber and issue
      const sub = await new Promise((resolve)=> db.get('SELECT id,email,tier,pro FROM subscribers WHERE id=?',[r.subscriber_id], (e,s)=> resolve(s)));
      const issue = r.issue_id ? await new Promise((resolve)=> db.get('SELECT id,title,reason,link,type,visibility FROM issues WHERE id=?',[r.issue_id], (e,i)=> resolve(i))) : null;
      if(!sub){
        db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['failed', r.id]);
        console.log(JSON.stringify({ event:'email_worker_skip', id: r.id, reason:'missing_subscriber' }));
        continue;
      }
      // normalize subscriber tier (support legacy pro int)
      const subTier = sub.tier || (typeof sub.pro !== 'undefined' ? (sub.pro==1 ? 'pro' : 'free') : undefined);
      // defense: ensure tier matches template
      if(issue){
        if(issue.visibility==='pro' && subTier!=='pro'){ db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['skipped', r.id]); console.log(JSON.stringify({ event:'email_worker_skip', id: r.id, reason:'subscriber_tier_mismatch', required: 'pro', subscriber_tier: subTier })); continue; }
        if(issue.visibility==='free' && subTier!=='free'){ db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['skipped', r.id]); console.log(JSON.stringify({ event:'email_worker_skip', id: r.id, reason:'subscriber_tier_mismatch', required: 'free', subscriber_tier: subTier })); continue; }
      } else {
        // allow templates that do not require an issue (welcome emails)
        console.log(JSON.stringify({ event:'email_worker_note', id: r.id, note:'issue_missing_allow_welcome', template: r.template, subscriber_tier: subTier }));
      }

      // load template
      const tplPath = path.join(__dirname,'templates', r.template + '.html');
      let html = '';
      try{ html = fs.readFileSync(tplPath,'utf8'); }catch(e){ console.log(JSON.stringify({ event:'email_worker_skip', id: r.id, reason:'template_missing', template: r.template })); db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['failed', r.id]); continue; }
      // simple interpolation
      html = html.replace(/{{title}}/g, (issue && issue.title) ? issue.title : '').replace(/{{reason}}/g, (issue && issue.reason) ? issue.reason : '').replace(/{{link}}/g, (issue && issue.link) ? issue.link : '#');

      if(!RESEND_KEY){
        // dry run
        console.log(JSON.stringify({ event:'email_send', provider:'resend', status:'dry_run', email: sub.email, template: r.template }));
        db.run('UPDATE email_queue SET status=? WHERE id=?', ['sent_dry', r.id]);
        processed++;
        continue;
      }
      // send via Resend API
      try{
        const payload = { from: FROM, to: sub.email, subject: `${r.template.replace(/_/g,' ')} — ${issue.title}`, html };
        const resp = await fetch('https://api.resend.com/emails',{ method:'POST', headers:{ 'Authorization':'Bearer '+RESEND_KEY,'Content-Type':'application/json' }, body: JSON.stringify(payload) });
        if(resp.ok){ db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['sent', r.id]); console.log(JSON.stringify({ event:'email_send', provider:'resend', status:'sent', email: sub.email, template: r.template })); processed++; }
        else { const text = await resp.text(); console.log(JSON.stringify({ event:'email_send', provider:'resend', status:'failed', email: sub.email, template: r.template, code: resp.status })); console.error('Resend error', resp.status, text); db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['failed', r.id]); }
      }catch(e){ console.log(JSON.stringify({ event:'email_send', provider:'resend', status:'exception', email: sub.email, template: r.template, error: String(e) })); console.error('Resend exception', e); db.run('UPDATE email_queue SET status=?, attempts=attempts+1 WHERE id=?', ['failed', r.id]); }
    }
    // log run summary
    console.log(JSON.stringify({ event:'email_worker_run', processed }));
    return res.json({ ok:true, processed });
  });
});

// Internal scheduler: run email worker every 10 minutes (600000ms)
if(!process.env.DISABLE_INTERNAL_SCHEDULER){
  const scheduleIntervalMs = 10*60*1000;
  setInterval(async ()=>{
    try{
      const url = (process.env.BASE_URL || BASE_URL).replace(/\/$/,'') + '/_worker/process-email?limit=100';
      const resp = await fetch(url, { method: 'POST' });
      const data = await resp.json().catch(()=>({ok:false}));
      const processed = data && data.processed ? data.processed : 0;
      console.log(JSON.stringify({ event:'email_worker_run', processed }));
    }catch(e){ console.error('Scheduler email worker invocation failed', e); }
  }, scheduleIntervalMs);
}

// Billing portal redirect (create session) — create session and redirect user
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

// Billing portal redirect for logged-in users: looks up subscriber by cookie and redirects to Stripe portal
app.get('/billing-portal-redirect', async (req,res)=>{
  const sid = req.cookies && req.cookies.tc_session;
  if(!sid) return res.status(401).json({ error: 'not_authenticated' });
  db.get('SELECT stripe_customer_id FROM subscribers WHERE id=?',[sid], async (err,row)=>{
    if(err) return res.status(500).json({ error: 'db_error' });
    if(!row || !row.stripe_customer_id) return res.status(400).json({ error: 'no_stripe_customer' });
    try{
      const Stripe = require('stripe');
      const stripe = Stripe(STRIPE_SECRET);
      const session = await stripe.billingPortal.sessions.create({ customer: row.stripe_customer_id, return_url: BASE_URL.replace(/\/$/,'/') });
      return res.redirect(session.url);
    }catch(e){ console.error('billing portal redirect error', e); return res.status(500).json({ error: 'stripe_error' }); }
  });
});

// Monthly guarantee: ensure at least one monthly_pro issue exists for current month
app.post('/admin/run-monthly-guarantee', (req,res)=>{
  const token = req.header('x-admin-token') || req.body.admin_token;
  if(!token || token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  const now = new Date();
  const yyyymm = `${now.getUTCFullYear()}-${String(now.getUTCMonth()+1).padStart(2,'0')}`;
  db.get('SELECT COUNT(1) AS c FROM issues WHERE type = ? AND published_for_month = ?', ['monthly_pro', yyyymm], (err,row)=>{
    if(err) return res.status(500).json({ error: 'db_error' });
    const count = (row && row.c) || 0;
    if(count>0) return res.json({ ok:true, message: 'monthly pick exists', count });
    // create fallback monthly_pro issue
    const id = uuidv4();
    const title = `Monthly pick — ${yyyymm}`;
    const reason = 'Fallback monthly pick to guarantee Pro delivery.';
    const ts = Date.now();
    const stmt = db.prepare('INSERT INTO issues (id,title,description,reason,link,score,ts,visibility,type,published_for_month) VALUES (?,?,?,?,?,?,?,?,?,?)');
    stmt.run(id, title, title, reason, null, 50, ts, 'pro', 'monthly_pro', yyyymm, (ierr)=>{
      if(ierr) return res.status(500).json({ error: 'db_error_insert' });
      // enqueue emails for pro subscribers
      db.all("SELECT id FROM subscribers WHERE tier='pro'", (se,subs)=>{
        if(se) return res.status(500).json({ error:'db_error_subs' });
        const insert = db.prepare('INSERT INTO email_queue (id,subscriber_id,issue_id,template,status,attempts,ts) VALUES (?,?,?,?,?,?,?)');
        let enq = 0;
        const nowTs = Date.now();
        (subs||[]).forEach(s=>{ try{ insert.run(uuidv4(), s.id, id, 'pro_monthly', 'pending', 0, nowTs); enq++; }catch(e){} });
        insert.finalize(()=>{ return res.json({ ok:true, created:true, id, enqueued:enq }); });
      });
    });
  });
});

// Admin status endpoint
app.get('/admin/status', (req,res)=>{
  const token = req.header('x-admin-token') || req.query.admin_token;
  if(!token || token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  db.get("SELECT COUNT(1) AS c FROM email_queue WHERE status='pending'", (e1,r1)=>{
    db.get("SELECT COUNT(1) AS c FROM subscribers WHERE tier='pro'", (e2,r2)=>{
      return res.json({ ok:true, pendingEmails: (r1 && r1.c)||0, proSubscribers: (r2 && r2.c)||0 });
    });
  });
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

// Override root to always serve latest repo index.html (bypass static caching at edge)
app.get('/', (req,res,next)=>{
  try{
    const indexPath = path.join(__dirname, '..', 'web-preview', 'index.html');
    const content = fs.readFileSync(indexPath,'utf8');
    res.set('Content-Type','text/html; charset=utf-8');
    res.set('Cache-Control','no-store');
    res.set('X-Served-By','trendcurator-backend-override');
    return res.send(content);
  }catch(e){ console.error('Failed to read index override', e); return next(); }
});

// Simple demo login: POST /login sets a session cookie (tc_session)
app.post('/login', (req,res)=>{
  const email = (req.body && req.body.email) ? String(req.body.email).trim().toLowerCase() : null;
  if(!email) return res.status(400).json({ error: 'email required' });
  // ensure subscriber exists (create if not)
  const ts = Date.now();
  db.get('SELECT id FROM subscribers WHERE email = ?', [email], (err,row)=>{
    if(err){ console.error('DB error on login', err); return res.status(500).json({ error: 'db_error' }); }
    const id = row ? row.id : uuidv4();
    const doSetCookie = ()=>{
      // set simple session cookie valid for 30 days
      const maxAge = 30*24*60*60*1000; // ms
      res.cookie('tc_session', id, { httpOnly: true, secure: process.env.NODE_ENV==='production', sameSite: 'lax', maxAge });
      // return success and redirect url
      return res.json({ ok:true, redirect: '/dashboard' });
    };
    if(row) return doSetCookie();
    // insert new subscriber
    const stmt = db.prepare('INSERT INTO subscribers (id,email,source,utm,ts,tier) VALUES (?,?,?,?,?,?)');
    stmt.run(id, email, 'demo-login', null, ts, 'free', (ierr)=>{
      if(ierr){ console.error('DB insert error on login', ierr); return res.status(500).json({ error: 'db_error' }); }
      console.log('[LOGIN] created subscriber via demo login', email);
      return doSetCookie();
    });
  });
});

// Claim session after checkout: user posts email used for payment and we set session to that subscriber
app.post('/claim-session', express.json(), (req,res)=>{
  const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase() : null;
  if(!email) return res.status(400).json({ error: 'email required' });
  db.get('SELECT id,pro,stripe_status FROM subscribers WHERE email = ?', [email], (err,row)=>{
    if(err) return res.status(500).json({ error: 'db_error' });
    if(!row) return res.status(404).json({ error: 'not_found' });
    const sid = row.id;
    // set cookie for this subscriber id
    const maxAge = 30*24*60*60*1000; // 30 days
    res.cookie('tc_session', sid, { httpOnly: true, secure: process.env.NODE_ENV==='production', sameSite: 'lax', maxAge, path: '/' });
    return res.json({ ok:true, id: sid, pro: row.pro===1, stripe_status: row.stripe_status });
  });
});

// Me endpoint: returns current session subscriber info
app.get('/me', (req,res)=>{
  const sid = req.cookies && req.cookies.tc_session;
  if(!sid) return res.json({ ok:false });
  db.get('SELECT email,pro,stripe_status FROM subscribers WHERE id=?', [sid], (err,row)=>{
    if(err) return res.status(500).json({ error:'db_error' });
    if(!row) return res.json({ ok:false });
    return res.json({ ok:true, email: row.email, pro: row.pro===1, stripe_status: row.stripe_status });
  });
});

// Dashboard: server-rendered members page
app.get('/dashboard', (req,res)=>{
  const sid = req.cookies && req.cookies.tc_session;
  if(!sid){
    // if not authenticated, redirect to public landing
    return res.status(302).redirect('/');
  }
  // fetch latest issue and recent issues
  db.get('SELECT id,title,description,reason,link,score,ts FROM issues ORDER BY ts DESC LIMIT 1', (err,latest)=>{
    if(err){ console.error('DB error fetching latest issue', err); return res.status(500).send('Server error'); }
    db.all('SELECT id,title,ts FROM issues ORDER BY ts DESC LIMIT 20', (err2,rows)=>{
      if(err2){ console.error('DB error fetching archive', err2); return res.status(500).send('Server error'); }
      // render simple HTML
      const latestHtml = latest ? `<h2>${escapeHtml(latest.title)}</h2><p class="muted">${escapeHtml(latest.reason)}</p><p><a href="${latest.link||'#'}" target="_blank">View product</a></p>` : '<p>No picks yet</p>';
      const archiveItems = (rows||[]).map(r=>`<li><a href="/archive.html#${r.id}">${escapeHtml(r.title)}</a></li>`).join('\n');
      const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dashboard — TrendCurator</title><style>body{font-family:Inter,system-ui,Arial,sans-serif;background:#0f1113;color:#e9edf0;padding:18px} .sidebar{width:260px;float:left;margin-right:18px} .main{margin-left:280px} a{color:#5fb3c8}</style></head><body><div class="sidebar"><h3>Latest Pick</h3>${latestHtml}<hr><h4>Archive</h4><ul>${archiveItems||'<li>No archive yet</li>'}</ul><hr><a href="/billing-portal-redirect">Manage billing</a><br/><a href="/logout">Logout</a></div><div class="main"><h1>Your dashboard</h1><p>Welcome back — here are your latest picks.</p></div></body></html>`;
      res.set('Content-Type','text/html; charset=utf-8');
      return res.send(html);
    });
  });
});

// Logout route
app.get('/logout',(req,res)=>{
  res.clearCookie('tc_session');
  return res.redirect('/');
});

// simple helper for escaping
function escapeHtml(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Serve other static assets
app.use('/', express.static(path.join(__dirname, '..', 'web-preview')));

app.listen(PORT, '0.0.0.0', ()=>{
  console.log(`TrendCurator backend listening on http://0.0.0.0:${PORT}`);
});
