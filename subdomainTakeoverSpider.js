const puppeteer = require('puppeteer');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');

let running = false;
let stopRequested = false;

function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Extended service fingerprints for takeover
const SERVICE_FINGERPRINTS = [
  { service: 'GitHub Pages', regex: /There isn't a GitHub Pages site here|Repository not found|404 Not Found/i },
  { service: 'Heroku', regex: /no such app|herokucdn.com error/i },
  { service: 'AWS S3', regex: /NoSuchBucket|The specified bucket does not exist|BucketNotFound/i },
  { service: 'Bitbucket', regex: /Repository not found|404/i },
  { service: 'Netlify', regex: /Not Found - Request ID|page not found/i },
  { service: 'Shopify', regex: /Sorry, this shop is currently unavailable/i },
  { service: 'Fastly', regex: /Fastly error: unknown domain/i },
  { service: 'Zendesk', regex: /Help Center Closed|subdomain not found/i },
  { service: 'Unbounce', regex: /The requested URL was not found on this server/i },
  { service: 'Tumblr', regex: /There's nothing here|Whatever you were looking for doesn't currently exist/i },
  { service: 'WordPress', regex: /Do you want to register/i },
  { service: 'Surge.sh', regex: /project not found/i },
  { service: 'Pantheon', regex: /404 error unknown site/i },
  { service: 'Azure', regex: /404 Web Site not found/i },
  { service: 'Read the Docs', regex: /unknown repository/i },
  { service: 'Statuspage', regex: /This page is parked/i },
  // New/extended fingerprints
  { service: 'Squarespace', regex: /No Such Site at This Address/i },
  { service: 'Cloudfront', regex: /ERROR: The request could not be satisfied/i },
  { service: 'Desk', regex: /Please contact your domain administrator/i },
  { service: 'Teamwork', regex: /Oops - We didn't find your site/i },
  { service: 'Helpjuice', regex: /We could not find what you're looking for/i },
  { service: 'Help Scout', regex: /No such app/i },
  { service: 'Cargo', regex: /404 Not Found|The page you were looking for doesn't exist/i },
  // ...add more as needed...
];

const ERROR_SIGNATURES = [
  /no such app/i,
  /there is no site here yet/i,
  /this domain is not configured/i,
  /repository not found/i,
  /this page is parked/i,
  /not found/i,
  /does not exist/i,
  /unavailable/i,
  /unknown domain/i,
  /help center closed/i,
  /subdomain not found/i,
  /project not found/i,
  /404/i,
  /error/i,
];

const CSRF_TOKEN_NAMES = [
  'csrf', 'xsrf', 'token', 'authenticity_token', 'csrfmiddlewaretoken', 'anticsrf', 'requesttoken'
];

const CORS_HEADERS = [
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-methods',
  'access-control-allow-headers'
];

async function resolveDNS(subdomain) {
  let result = { A: [], CNAME: [], NS: [], DNSSEC: false };
  try { result.A = await dns.resolve4(subdomain); } catch {}
  try { result.CNAME = await dns.resolveCname(subdomain); } catch {}
  try { result.NS = await dns.resolveNs(subdomain); } catch {}
  // DNSSEC check
  try {
    const res = await dns.resolveDnssec(subdomain, 'A');
    if (res && res.length) result.DNSSEC = true;
  } catch {}
  return result;
}

async function fetchUrl(url, userAgent = null, cookies = '') {
  return new Promise((resolve) => {
    try {
      const urlObj = new URL(url);
      const isHttps = urlObj.protocol === 'https:';
      const options = {
        method: 'GET',
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        headers: {
          'User-Agent': userAgent || 'Mozilla/5.0 (SubdomainSpider)',
          'Cookie': cookies
        },
        timeout: 10000,
      };
      const req = (isHttps ? https : http).request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk.toString(); });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: body.slice(0, 5000), // Larger snippet for deeper analysis
          });
        });
      });
      req.on('error', (e) => {
        send('log', `HTTP error for ${url}: ${e.message}`, 'error');
        resolve({ status: 0, headers: {}, body: '' });
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '' }); });
      req.end();
    } catch (e) {
      send('log', `Fetch error for ${url}: ${e.message}`, 'error');
      resolve({ status: 0, headers: {}, body: '' });
    }
  });
}

function extractSubdomains(text, rootDomains) {
  // Extract all hostnames and subdomains from text
  const found = [];
  const regex = /([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}/g;
  let match;
  while ((match = regex.exec(text))) {
    const host = match[0].toLowerCase();
    // Only include subdomains of rootDomains
    if (rootDomains.some(root => host.endsWith(root))) found.push(host);
  }
  return found;
}

function extractLinks(html, baseUrl, rootDomains) {
  // Extract all in-scope links from HTML
  const links = [];
  const regex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1/gi;
  let match;
  while ((match = regex.exec(html))) {
    let href = match[2];
    try {
      let url = new URL(href, baseUrl);
      if (rootDomains.some(root => url.hostname.endsWith(root))) {
        links.push(url.toString());
      }
    } catch {}
  }
  return links;
}

function extractCSRF(html) {
  // Look for CSRF tokens in forms and meta tags
  const tokens = [];
  const inputRegex = /<input[^>]+name=["']?([^"'>\s]+)["']?[^>]*value=["']?([^"'>\s]+)["']?/gi;
  let match;
  while ((match = inputRegex.exec(html))) {
    const name = match[1].toLowerCase();
    if (CSRF_TOKEN_NAMES.some(t => name.includes(t))) {
      tokens.push({ name, value: match[2] });
    }
  }
  // Meta tags
  const metaRegex = /<meta[^>]+name=["']?([^"'>\s]+)["']?[^>]*content=["']?([^"'>\s]+)["']?/gi;
  while ((match = metaRegex.exec(html))) {
    const name = match[1].toLowerCase();
    if (CSRF_TOKEN_NAMES.some(t => name.includes(t))) {
      tokens.push({ name, value: match[2] });
    }
  }
  return tokens;
}

function analyzeCORS(headers, origin) {
  // Analyze CORS headers for misconfigurations
  let issues = [];
  const allowOrigin = headers['access-control-allow-origin'];
  if (allowOrigin) {
    if (allowOrigin === '*' && headers['access-control-allow-credentials'] === 'true') {
      issues.push('CORS: Wildcard origin with credentials allowed (critical)');
    }
    if (origin && allowOrigin === origin) {
      issues.push('CORS: Reflection of Origin header');
    }
  } else {
    issues.push('CORS: No Access-Control-Allow-Origin header');
  }
  // Check for other CORS headers
  for (const h of CORS_HEADERS) {
    if (!headers[h]) issues.push(`CORS: Missing header ${h}`);
  }
  return issues;
}

function analyzeCSRF(tokens, html, url) {
  // Analyze CSRF tokens for presence and strength
  if (!tokens.length) return ['CSRF: No CSRF token found in forms or meta tags'];
  let issues = [];
  for (const t of tokens) {
    if (!t.value || t.value.length < 8) issues.push(`CSRF: Weak or empty token (${t.name})`);
    if (/^(1234|test|csrf|token)$/i.test(t.value)) issues.push(`CSRF: Default/guessable token (${t.name})`);
  }
  return issues;
}

function analyzeSecurityHeaders(headers) {
  // Check for common security headers
  const required = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'x-xss-protection'
  ];
  let missing = [];
  for (const h of required) {
    if (!headers[h]) missing.push(`Missing security header: ${h}`);
  }
  return missing;
}

async function crawlAndExtractSubdomainsAndLinks(page, url, rootDomains, scanMode, visitedLinks) {
  let subdomains = [];
  let newLinks = [];
  let csrfFindings = [];
  let corsFindings = [];
  let securityHeaderFindings = [];
  try {
    send('log', `Navigating to ${url}`, 'action');
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    // await page.waitForTimeout(1000);
    await new Promise(r => setTimeout(r, 1000));
    const html = await page.content();
    subdomains = subdomains.concat(extractSubdomains(html, rootDomains));
    newLinks = extractLinks(html, url, rootDomains);

    // CSRF token analysis
    const csrfTokens = extractCSRF(html);
    csrfFindings = analyzeCSRF(csrfTokens, html, url);
    if (csrfTokens.length) {
      send('log', `CSRF tokens found: ${csrfTokens.map(t => t.name).join(', ')}`, 'info');
    }

    // Extract from JS files
    const jsLinks = await page.$$eval('script[src]', els => els.map(e => e.src));
    for (const jsUrl of jsLinks) {
      if (scanMode === 'passive') continue;
      try {
        const jsResp = await fetchUrl(jsUrl);
        subdomains = subdomains.concat(extractSubdomains(jsResp.body, rootDomains));
        newLinks = newLinks.concat(extractLinks(jsResp.body, jsUrl, rootDomains));
      } catch {}
    }

    // Extract from headers
    const resp = await fetchUrl(url);
    for (const key of Object.keys(resp.headers)) {
      subdomains = subdomains.concat(extractSubdomains(resp.headers[key] + '', rootDomains));
    }
    // CORS analysis
    corsFindings = analyzeCORS(resp.headers, url);
    if (corsFindings.length) send('log', `CORS findings for ${url}: ${corsFindings.join('; ')}`, 'warn');
    // Security headers
    securityHeaderFindings = analyzeSecurityHeaders(resp.headers);

    // Extract from Location/CORS headers
    if (resp.headers['location']) subdomains = subdomains.concat(extractSubdomains(resp.headers['location'], rootDomains));
    if (resp.headers['access-control-allow-origin']) subdomains = subdomains.concat(extractSubdomains(resp.headers['access-control-allow-origin'], rootDomains));

    // Extract from robots.txt and sitemap.xml
    if (scanMode === 'active') {
      for (const special of ['/robots.txt', '/sitemap.xml']) {
        try {
          const specialUrl = new URL(url);
          specialUrl.pathname = special;
          const specialResp = await fetchUrl(specialUrl.toString());
          subdomains = subdomains.concat(extractSubdomains(specialResp.body, rootDomains));
          newLinks = newLinks.concat(extractLinks(specialResp.body, specialUrl.toString(), rootDomains));
        } catch {}
      }
    }

    // Extract from inline JS
    const inlineJs = await page.$$eval('script:not([src])', els => els.map(e => e.innerText).join('\n'));
    subdomains = subdomains.concat(extractSubdomains(inlineJs, rootDomains));
    newLinks = newLinks.concat(extractLinks(inlineJs, url, rootDomains));

    // Extract from src, href, action, data-* attributes
    const attrs = await page.evaluate(() => {
      const attrs = [];
      document.querySelectorAll('*').forEach(el => {
        ['src', 'href', 'action'].forEach(attr => {
          if (el.hasAttribute && el.hasAttribute(attr)) attrs.push(el.getAttribute(attr));
        });
        Array.from(el.attributes || []).forEach(a => {
          if (a.name.startsWith('data-')) attrs.push(a.value);
        });
      });
      return attrs;
    });
    for (const val of attrs) {
      if (typeof val === 'string') {
        subdomains = subdomains.concat(extractSubdomains(val, rootDomains));
        newLinks = newLinks.concat(extractLinks(val, url, rootDomains));
      }
    }

    // Extract from config files (config.json, settings.js)
    if (scanMode === 'active') {
      for (const config of ['/config.json', '/settings.js']) {
        try {
          const configUrl = new URL(url);
          configUrl.pathname = config;
          const configResp = await fetchUrl(configUrl.toString());
          subdomains = subdomains.concat(extractSubdomains(configResp.body, rootDomains));
          newLinks = newLinks.concat(extractLinks(configResp.body, configUrl.toString(), rootDomains));
        } catch {}
      }
    }

    // Deduplicate
    subdomains = [...new Set(subdomains)];
    newLinks = [...new Set(newLinks)].filter(l => !visitedLinks.has(l));
  } catch (e) {
    send('log', `Error crawling ${url}: ${e.message}`, 'error');
  }
  return { subdomains, newLinks, csrfFindings, corsFindings, securityHeaderFindings };
}

function matchService(body) {
  for (const fp of SERVICE_FINGERPRINTS) {
    if (fp.regex.test(body)) return fp.service;
  }
  return '';
}

function matchErrorSignature(body) {
  for (const sig of ERROR_SIGNATURES) {
    if (sig.test(body)) return sig.toString();
  }
  return '';
}

async function spider(opts) {
  running = true;
  stopRequested = false;
  let progress = 0;
  let found = 0;
  const visited = new Set();
  const visitedLinks = new Set();
  const subdomainCache = new Map();
  const queue = [];
  const rootDomains = opts.urls.map(u => {
    try { return (new URL(u)).hostname.split('.').slice(-2).join('.'); } catch { return ''; }
  }).filter(Boolean);

  for (const url of opts.urls) queue.push(url);

  send('log', `Scope: ${opts.urls.length} URLs. Starting Subdomain Takeover spider...`, 'info');

  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();

  let allSubdomains = new Set();
  let allLinks = new Set(queue);

  // Autonomous, adaptive crawling (BFS)
  while (queue.length && !stopRequested) {
    const url = queue.shift();
    if (visitedLinks.has(url)) continue;
    visitedLinks.add(url);
    progress++;
    send('progress', progress);

    send('log', `Crawling: ${url}`, 'info');
    let crawlResult = {};
    try {
      crawlResult = await crawlAndExtractSubdomainsAndLinks(page, url, rootDomains, opts.scanMode, visitedLinks);
    } catch (e) {
      send('log', `Crawl error: ${e.message}`, 'error');
      continue;
    }
    for (const sub of crawlResult.subdomains) allSubdomains.add(sub);
    for (const l of crawlResult.newLinks) {
      if (!visitedLinks.has(l)) {
        queue.push(l);
        allLinks.add(l);
      }
    }
    // Report CSRF/CORS/security header findings
    for (const finding of crawlResult.csrfFindings) {
      send('finding', {
        url,
        type: 'CSRF',
        status: 'Potential Issue',
        reason: finding
      });
    }
    for (const finding of crawlResult.corsFindings) {
      send('finding', {
        url,
        type: 'CORS',
        status: 'Potential Issue',
        reason: finding
      });
    }
    for (const finding of crawlResult.securityHeaderFindings) {
      send('finding', {
        url,
        type: 'SecurityHeader',
        status: 'Missing',
        reason: finding
      });
    }
    await sleep(100);
  }

  // Check each subdomain for takeover and protections
  let subProgress = 0;
  let vulnCount = 0;
  for (const sub of allSubdomains) {
    if (stopRequested) break;
    subProgress++;
    send('log', `Checking subdomain: ${sub}`, 'action');
    let dnsInfo = { A: [], CNAME: [], NS: [], DNSSEC: false };
    let status = 'Unknown';
    let reason = '';
    let service = '';
    let responseSnippet = '';
    let protections = [];
    if (subdomainCache.has(sub)) {
      dnsInfo = subdomainCache.get(sub);
    } else if (opts.scanMode === 'active') {
      dnsInfo = await resolveDNS(sub);
      subdomainCache.set(sub, dnsInfo);
    }
    if (opts.scanMode === 'active') {
      const resp = await fetchUrl('http://' + sub);
      responseSnippet = resp.body;
      // If DNS resolves but HTTP returns error or signature
      if (
        (resp.status === 404 || resp.status === 403 || resp.status === 400 || resp.status === 502 || resp.status === 0) ||
        matchErrorSignature(resp.body)
      ) {
        status = 'Potential Takeover';
        reason = matchErrorSignature(resp.body) || `HTTP status ${resp.status}`;
        service = matchService(resp.body);
        vulnCount++;
      } else {
        status = 'No Issue';
        reason = `HTTP status ${resp.status}`;
      }
      // Check for protections
      if (dnsInfo.DNSSEC) protections.push('DNSSEC enabled');
      const secHeaders = analyzeSecurityHeaders(resp.headers);
      if (secHeaders.length) protections.push(...secHeaders);
      // CORS check
      const corsFindings = analyzeCORS(resp.headers, sub);
      if (corsFindings.length) protections.push(...corsFindings);
    } else {
      // Passive: just DNS info
      status = (dnsInfo.CNAME.length > 0) ? 'CNAME Found' : 'No CNAME';
      reason = dnsInfo.CNAME.join(', ');
      if (dnsInfo.DNSSEC) protections.push('DNSSEC enabled');
    }
    send('finding', {
      subdomain: sub,
      status,
      reason,
      dns: `A: ${dnsInfo.A.join(',')} CNAME: ${dnsInfo.CNAME.join(',')} NS: ${dnsInfo.NS.join(',')} DNSSEC: ${dnsInfo.DNSSEC}`,
      service,
      protections: protections.join('; '),
      response: responseSnippet
    });
    if (status === 'Potential Takeover') send('found', vulnCount);
    await sleep(50);
  }

  await browser.close();
  send('status', 'Idle');
  running = false;
}

process.on('message', async (msg) => {
  if (!msg || !msg.type) return;
  if (msg.type === 'start') {
    send('clear');
    send('status', 'Running');
    try {
      await spider(msg.data);
    } catch (e) {
      send('log', `Fatal error: ${e.message}`, 'error');
    }
    send('status', 'Idle');
  } else if (msg.type === 'stop') {
    stopRequested = true;
    send('log', 'Stop requested.', 'action');
    send('status', 'Stopped');
  }
});
