const Database = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '.data');
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'data.sqlite');

try{fs.mkdirSync(DATA_DIR, { recursive: true })}catch(e){}

const db = new Database(DB_PATH);

const picks = [
  {
    title: 'This week: Insulated Bottle',
    description: 'Clean edition, high demand',
    reason: 'Durable + repeat accessories',
    link: 'https://example.com',
    score: 86,
    tags: ['home','wellness']
  },
  {
    title: 'Compact Air Purifier — Quiet Home',
    description: 'Portable HEPA purifier for bedrooms and offices',
    reason: 'Search momentum + indoor air focus',
    link: 'https://example.com/air',
    score: 79,
    tags: ['home','wellness']
  },
  {
    title: 'Smart Sleep Light — Gentle Wake',
    description: 'Circadian-friendly dawn-simulating light',
    reason: 'TikTok interest + repeat use',
    link: 'https://example.com/sleep',
    score: 75,
    tags: ['health','smart']
  },
  {
    title: 'Minimal Desk Organizer — Clean Setup',
    description: 'Modular organizer for modern desks',
    reason: 'Aesthetic trend + repeat purchases for accessories',
    link: 'https://example.com/desk',
    score: 72,
    tags: ['home','office']
  },
  {
    title: 'Eco Laundry Strips — Low Waste',
    description: 'Lightweight, plastic-free detergent strips',
    reason: 'Sustainable product searches rising',
    link: 'https://example.com/laundry',
    score: 70,
    tags: ['eco','home']
  },
  {
    title: 'Compact Projector — Tiny Cinema',
    description: 'Pocket projector for streaming and presentations',
    reason: 'Holiday season social buzz + gift potential',
    link: 'https://example.com/projector',
    score: 68,
    tags: ['electronics','entertainment']
  },
  {
    title: 'Reusable Silicone Food Covers',
    description: 'Stretchable covers to replace clingfilm',
    reason: 'Searches + repeat households buying sets',
    link: 'https://example.com/covers',
    score: 65,
    tags: ['kitchen','eco']
  },
  {
    title: 'Instant Read Thermometer — 0.5s',
    description: 'Fast, accurate meat & grill thermometer',
    reason: 'Consistent bestseller signals on Amazon',
    link: 'https://example.com/thermo',
    score: 64,
    tags: ['kitchen','gadgets']
  },
  {
    title: 'Ergonomic Laptop Stand — CoolFlow',
    description: 'Aluminium stand with airflow',
    reason: 'Remote work staples + accessory ecosystem',
    link: 'https://example.com/stand',
    score: 63,
    tags: ['office','tech']
  },
  {
    title: 'Vitamin D Compact Lamp — Winter Boost',
    description: 'Desk lamp emitting therapeutic wavelengths',
    reason: 'Seasonal searches + wellness trend',
    link: 'https://example.com/vitd',
    score: 60,
    tags: ['health','wellness']
  }
];

db.serialize(()=>{
  const stmt = db.prepare('INSERT OR IGNORE INTO issues (id,title,description,reason,link,score,ts) VALUES (?,?,?,?,?,?,?)');
  const { v4: uuidv4 } = require('uuid');
  picks.forEach(p=>{
    const id = uuidv4();
    const ts = Date.now();
    stmt.run(id, p.title, p.description, p.reason, p.link, p.score, ts);
    console.log('Seeded:', p.title);
  });
  stmt.finalize(()=>{
    db.close();
    console.log('Seeding complete. DB at', DB_PATH);
  });
});
