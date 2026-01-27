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
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`; // used to build issue URLs in responses
// DATA_DIR handling: prefer explicit env var; when on Render and DATA_DIR not set, default to Render-friendly workspace
const DEFAULT_RENDER_DATA_DIR = '/opt/render/project/src/backend/.data';
const DATA_DIR = process.env.DATA_DIR || (process.env.RENDER ? DEFAULT_RENDER_DATA_DIR : path.join(__dirname, '.data'));
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'data.sqlite');

// Ensure data dir exists
try{fs.mkdirSync(DATA_DIR, { recursive: true })}catch(e){console.error('Failed to create DATA_DIR', e)}

// Ensure db dir
try{fs.mkdirSync(path.dirname(DB_PATH), { recursive: true })}catch(e){console.error('Failed to create DB dir', e)}

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
});

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
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
app.post('/signup', async (req, res) => {
  const { error, value } = signupSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  const ts = Date.now();
  try{
    // check if email exists
    db.get('SELECT id FROM subscribers WHERE email = ?', [value.email], (err,row)=>{
      if(err){ console.error('DB error', err); return res.status(500).json({ error: 'Database error' }); }
      if(row){
        // friendly response when already subscribed
        console.log(`[EMAIL STUB] Signup attempted for existing email: ${value.email}`);
        return res.status(200).json({ ok: true, id: row.id, message: 'already_subscribed' });
      }
      const id = uuidv4();
      const stmt = db.prepare('INSERT INTO subscribers (id,email,source,utm,ts) VALUES (?,?,?,?,?)');
      stmt.run(id, value.email, value.source || null, value.utm || null, ts, function(insertErr){
        if(insertErr){ console.error('DB error',insertErr); return res.status(500).json({ error: 'Database error' }); }
        console.log(`[EMAIL STUB] New signup: ${value.email} source=${value.source||''} utm=${value.utm||''}`);
        return res.json({ ok: true, id });
      });
    });
  }catch(e){
    console.error('Signup exception', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/publish', (req, res) => {
  const token = req.header('x-admin-token') || req.query.admin_token || req.body.admin_token;
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  const { error, value } = publishSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  const id = uuidv4();
  const ts = Date.now();
  const stmt = db.prepare('INSERT INTO issues (id,title,description,reason,link,score,ts) VALUES (?,?,?,?,?,?,?)');
  stmt.run(id, value.title, value.description, value.reason, value.link||null, value.score||null, ts, function(err){
    if(err){
      console.error('DB error',err);
      return res.status(500).json({ error: 'Database error' });
    }
    db.get('SELECT COUNT(1) AS c FROM subscribers', (err2,row)=>{
      const count = (row && row.c) || 0;
      console.log(JSON.stringify({event:'publish', id, title:value.title, subscribers:count, ts}));
      const issueUrl = `${BASE_URL}/archive.html#${id}`;
      return res.json({ ok: true, id, url: issueUrl });
    });
  });
});

app.get('/issues', (req, res) => {
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
app.use('/', express.static(path.join(__dirname, '..', 'web-preview')));

app.listen(PORT, '0.0.0.0', ()=>{
  console.log(`TrendCurator backend listening on http://0.0.0.0:${PORT}`);
});
