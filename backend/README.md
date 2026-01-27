TrendCurator backend (MVP)

Requirements
- Node.js 18+ recommended
- No paid services required for local dev

Install

  cd backend
  npm install

Environment
- ADMIN_TOKEN - token string used to authenticate /publish (default: changeme_admin_token)
- PORT - optional port (default: 8787). Render will provide PORT and expects the service to bind 0.0.0.0
- BASE_URL - public base URL for your service (used to build links in publish responses). Optional; if not set then on Render it defaults to https://trendcurator.onrender.com; locally it defaults to http://localhost:<PORT>
- DATA_DIR - directory where SQLite DB will be stored.
  - Default (local): ./ .data
  - Recommended for Render (free tier): /opt/render/project/src/backend/.data
    (Do NOT set /var/data unless you have attached a paid persistent disk.)
- DB_PATH - optional path to sqlite file (default: <DATA_DIR>/data.sqlite)

Run (local)

  ADMIN_TOKEN=supersecret node server.js

Render deploy (recommended for public preview)
1) Create a Render account (https://render.com)
2) Connect your GitHub repo and create a new Web Service
   - Environment: Node
   - Branch: main (or your branch)
   - Build Command: cd backend && npm install
   - Start Command: cd backend && npm start
   - Instance Type: Free (or as desired)
3) Environment variables (set in Render service settings):
   - ADMIN_TOKEN: set to a strong secret (e.g. SUPERSECRET)
   - DATA_DIR: /opt/render/project/src/backend/.data
   - BASE_URL: https://trendcurator.onrender.com  (recommended; if unset, the server will default to this on Render)
4) Deploy. Render will build and start the service and provide a public URL.

Important: trust proxy on Render
- Render runs services behind a proxy. For correct client IP detection and to avoid errors from express-rate-limit, the app must enable trust proxy.
- This project sets it automatically in backend/server.js with:

    app.set('trust proxy', 1);

Endpoints
- POST /signup
  Body: { email, source?, utm? }
  Stores subscriber and logs to console. Rate limited to 10/min per IP.

  Example cURL:

    curl -X POST https://<YOUR-SERVICE>.onrender.com/signup \
      -H "Content-Type: application/json" \
      -d '{"email":"you@example.com","source":"x_post","utm":"utm_campaign=pilot"}'

- POST /publish
  Header: x-admin-token: <ADMIN_TOKEN> OR body/admin_token
  Body: { title, description, reason, link?, score? }
  Publishes an issue (stores in sqlite). Email sending is stubbed and logged to console.

  Example cURL (use your ADMIN_TOKEN):

    curl -X POST https://<YOUR-SERVICE>.onrender.com/publish \
      -H "Content-Type: application/json" \
      -H "X-Admin-Token: your_admin_token_here" \
      -d '{"title":"This week: Insulated Bottle","description":"Short description","reason":"Why we like it","link":"https://example.com","score":86}'

  Response includes the public URL for the new issue:

    { "ok": true, "id": "...", "url": "https://<YOUR-SERVICE>.onrender.com/archive.html#<id>" }

- GET /issues
  Returns list of published issues (archive)

- GET /issues/:id
  Returns single issue

- GET /health
  Returns a simple health check JSON { ok: true, ts: <timestamp> }

Notes
- The frontend preview (web-preview/index.html) is served at / when running the server.
- Archive page available at /archive.html (lists issues).
- The admin token is stored as an environment variable (ADMIN_TOKEN). For quick dev you can run:

    ADMIN_TOKEN=supersecret node server.js

- Email sending is stubbed: publishes log entries to the server console. No paid services required for MVP.

Security & next steps
- This MVP uses a single-token admin approach. For production, add authenticated user accounts, rotateable tokens, rate limits on publish, and background send queues.

License: MIT
