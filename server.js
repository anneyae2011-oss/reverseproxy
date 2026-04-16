const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { createProxyMiddleware } = require('http-proxy-middleware');
const fs = require('fs');
const path = require('path');

const app = express();
const CONFIG_PATH = path.join(__dirname, 'config.json');
const ADMIN_PASSWORD = 'enyapeakshit';
const API_KEY = 'enyapeakshit';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'proxy-secret-key',
  resave: false,
  saveUninitialized: false
}));
app.use(express.static('public'));

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return { sessionKey: '', proxyTarget: '', proxyPath: '/proxy' };
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Login
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Wrong password' });
  }
});

// Logout
app.post('/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Get config
app.get('/admin/config', requireAuth, (req, res) => {
  res.json(loadConfig());
});

// Save config
app.post('/admin/config', requireAuth, (req, res) => {
  const { sessionKey, proxyTarget, proxyPath } = req.body;
  const cfg = { sessionKey, proxyTarget, proxyPath: proxyPath || '/proxy' };
  saveConfig(cfg);

  // Re-register proxy with new config
  setupProxy(cfg);

  res.json({ success: true });
});

// API key middleware
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (key === API_KEY) return next();
  res.status(401).json({ error: 'Invalid or missing API key' });
}

// Single unified API endpoint — all proxy requests go through here
// POST /api/proxy
// Headers: x-api-key: enyapeakshit
// Body: { path: '/v1/messages', method: 'POST', headers: {}, body: {} }
app.all('/api/proxy*', requireApiKey, (req, res, next) => {
  if (!proxyMiddleware) {
    return res.status(503).json({ error: 'Proxy not configured. Set a target in the admin panel.' });
  }
  proxyMiddleware(req, res, next);
});

// Dynamic proxy handler
let proxyMiddleware = null;
let currentProxyPath = '/proxy';

function setupProxy(cfg) {
  if (!cfg.proxyTarget) return;

  proxyMiddleware = createProxyMiddleware({
    target: cfg.proxyTarget,
    changeOrigin: true,
    pathRewrite: { '^/api/proxy': '' },
    on: {
      proxyReq: (proxyReq) => {
        if (cfg.sessionKey) {
          proxyReq.setHeader('Cookie', `sessionKey=${cfg.sessionKey}`);
          proxyReq.setHeader('Authorization', `Bearer ${cfg.sessionKey}`);
        }
        // Strip the internal API key before forwarding
        proxyReq.removeHeader('x-api-key');
      }
    }
  });

  currentProxyPath = cfg.proxyPath || '/proxy';
}

// Legacy proxy route
app.use((req, res, next) => {
  if (req.path.startsWith(currentProxyPath) && proxyMiddleware) {
    return proxyMiddleware(req, res, next);
  }
  next();
});

// Init proxy on startup
setupProxy(loadConfig());

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
});
