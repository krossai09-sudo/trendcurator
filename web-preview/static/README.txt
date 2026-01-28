This folder contains extracted JS files for the frontend to allow strict CSP.

Files:
- app.js     -> main site JS (signup, hero refresh, admin injection, pro modal)
- archive.js -> archive page JS (fetch /issues and render list)

Usage: include these files from index.html and archive.html as <script src="/static/app.js" defer></script>

After deploying, we can remove 'unsafe-inline' from CSP (already done in backend/server.js) and keep a strict CSP with script-src 'self'.
