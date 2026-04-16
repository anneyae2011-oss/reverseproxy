const { sha3_256 } = require('js-sha3');

// Solve DeepSeek's proof-of-work challenge
async function solvePoW(token) {
  console.log('[PoW] fetching challenge...');
  const challengeRes = await fetch('https://chat.deepseek.com/api/v0/chat/create_pow_challenge', {
    method: 'POST',
    signal: AbortSignal.timeout(10000),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
      'Referer': 'https://chat.deepseek.com/',
      'Origin': 'https://chat.deepseek.com',
      'x-app-version': '20241129.1',
      'x-client-locale': 'en_US',
      'x-client-platform': 'web',
      'x-client-version': '1.8.0'
    },
    body: JSON.stringify({ target_path: '/api/v0/chat/completion' })
  });
  const json = await challengeRes.json();
  if (!json.data?.biz_data) throw new Error('PoW challenge failed: ' + JSON.stringify(json));
  const { algorithm, challenge, salt, difficulty, signature } = json.data.biz_data.challenge;
  console.log('[PoW] difficulty:', difficulty);

  // DeepSeekHashV1: find answer where first 4 bytes of sha3_256 as uint32 < (0xFFFFFFFF / difficulty)
  const target = Math.floor(0xFFFFFFFF / difficulty);
  let answer = 0;
  await new Promise(resolve => {
    function step() {
      for (let i = 0; i < 5000; i++) {
        const hash = sha3_256(`${challenge}${salt}${answer}`);
        const val = parseInt(hash.slice(0, 8), 16);
        if (val < target) return resolve();
        answer++;
      }
      setImmediate(step);
    }
    step();
  });

  console.log(`[PoW] solved answer=${answer}`);
  return JSON.stringify({ algorithm, challenge, salt, answer, signature, target_path: '/api/v0/chat/completion' });
}
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
  setupProxy(cfg);
  res.json({ success: true });
});

// Known static model lists for web-app targets that don't expose a models API
const STATIC_MODELS = {
  'chat.deepseek.com': [
    'deepseek-chat',
    'deepseek-reasoner',
  ],
  'arena.ai': ['(configure via arena.ai UI)']
};

// Fetch models from the configured proxy target
app.get('/admin/models', requireAuth, async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.proxyTarget) return res.status(400).json({ error: 'No proxy target configured' });

  // Check if target matches a known static list
  for (const [host, models] of Object.entries(STATIC_MODELS)) {
    if (cfg.proxyTarget.includes(host)) {
      return res.json({ models, static: true });
    }
  }

  // Otherwise try common API endpoints
  const endpoints = ['/v1/models', '/api/v1/models', '/models'];
  for (const ep of endpoints) {
    try {
      const url = cfg.proxyTarget.replace(/\/$/, '') + ep;
      const headers = { 'Content-Type': 'application/json' };
      if (cfg.sessionKey) {
        headers['Authorization'] = `Bearer ${cfg.sessionKey}`;
        headers['Cookie'] = cfg.sessionKey;
      }
      const response = await fetch(url, { headers });
      if (!response.ok) continue;
      const data = await response.json();
      const models = data.data || data.models || data || [];
      const list = Array.isArray(models)
        ? models.map(m => (typeof m === 'string' ? m : m.id || m.name || JSON.stringify(m)))
        : Object.keys(models);
      return res.json({ models: list, endpoint: ep });
    } catch (_) {
      continue;
    }
  }

  res.status(502).json({ error: 'Could not fetch models from proxy target' });
});

// API key middleware
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key']
    || req.query.api_key
    || (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (key === API_KEY) return next();
  res.status(401).json({ error: 'Invalid or missing API key' });
}

// OpenAI-compatible /v1/models endpoint for clients like SillyTavern
app.get('/api/proxy/v1/models', requireApiKey, (req, res) => {
  const cfg = loadConfig();
  const models = STATIC_MODELS[Object.keys(STATIC_MODELS).find(k => cfg.proxyTarget && cfg.proxyTarget.includes(k))] || [];
  res.json({
    object: 'list',
    data: models.map(id => ({ id, object: 'model', created: 0, owned_by: 'proxy' }))
  });
});

// OpenAI-compatible /v1/chat/completions — translates to deepseek web API format
app.post('/api/proxy/v1/chat/completions', requireApiKey, async (req, res) => {
  console.log('[chat/completions] hit');
  const cfg = loadConfig();
  if (!cfg.proxyTarget) return res.status(503).json({ error: 'Proxy not configured' });

  // If target is deepseek chat web app, translate the request
  if (cfg.proxyTarget.includes('chat.deepseek.com')) {
    const { messages, model } = req.body;
    const lastMessage = messages && messages.filter(m => m.role === 'user').pop();
    const prompt = lastMessage ? lastMessage.content : '';

    const deepseekBody = {
      chat_session_id: require('crypto').randomUUID(),
      parent_message_id: null,
      prompt,
      ref_file_ids: [],
      search_enabled: false,
      thinking_enabled: model === 'deepseek-reasoner',
      model_type: model === 'deepseek-reasoner' ? 'reasoner' : 'default',
      preempt: false
    };

    try {
      const powResponse = await solvePoW(cfg.sessionKey);
      console.log('[PoW] solved');
      const response = await fetch('https://chat.deepseek.com/api/v0/chat/completion', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${cfg.sessionKey}`,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
          'Referer': 'https://chat.deepseek.com/',
          'Origin': 'https://chat.deepseek.com',
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'x-app-version': '20241129.1',
          'x-client-locale': 'en_US',
          'x-client-platform': 'web',
          'x-client-version': '1.8.0',
          'x-client-timezone-offset': '28800',
          'x-ds-pow-response': powResponse
        },
        body: JSON.stringify(deepseekBody)
      });

      console.log('[DeepSeek]', response.status);

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        console.log('[raw]', JSON.stringify(chunk.slice(0, 300)));
        buffer += chunk;
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data:')) continue;
          const data = line.slice(5).trim();
          if (!data || data === '[DONE]') continue;
          try {
            const parsed = JSON.parse(data);
            console.log('[DS chunk]', JSON.stringify(parsed).slice(0, 200));
            const content = parsed?.choices?.[0]?.delta?.content
              || parsed?.data?.content
              || '';
            if (!content) continue;
            const chunk = {
              id: 'chatcmpl-proxy',
              object: 'chat.completion.chunk',
              created: Math.floor(Date.now() / 1000),
              model: model || 'deepseek-chat',
              choices: [{ index: 0, delta: { content }, finish_reason: null }]
            };
            res.write(`data: ${JSON.stringify(chunk)}\n\n`);
          } catch (_) {}
        }
      }

      res.write('data: [DONE]\n\n');
      res.end();
    } catch (e) {
      console.error('[error]', e.message);
      res.status(502).json({ error: e.message });
    }
    return;
  }

  // For other targets, proxy normally
  if (!proxyMiddleware) return res.status(503).json({ error: 'Proxy not configured' });
  proxyMiddleware(req, res, () => {});
});

// Catch-all proxy for everything else under /api/proxy
app.all('/api/proxy/*', requireApiKey, (req, res, next) => {
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
          // Send as both cookie and bearer — works for both API keys and session cookies
          proxyReq.setHeader('Cookie', cfg.sessionKey);
          proxyReq.setHeader('Authorization', `Bearer ${cfg.sessionKey}`);
        }
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
