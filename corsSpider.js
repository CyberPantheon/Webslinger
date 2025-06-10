const puppeteer = require('puppeteer');

let running = false;
let stopRequested = false;

function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomOrigin() {
  const domains = [
    'evil.c0rs-spider.com',
    'attacker.com',
    'malicious.site',
    'sub.attacker.com',
    'cors-tester.xyz',
    'test-origin.net'
  ];
  const idx = Math.floor(Math.random() * domains.length);
  return `https://${domains[idx]}`;
}

function isSensitiveEndpoint(url) {
  return /(account|user|token|api|auth|login|session|password|profile|settings|admin|secure|cart|checkout|order|payment|fund|bank)/i.test(url);
}

function summarizeCorsHeaders(headers) {
  const aco = headers['access-control-allow-origin'] || '';
  const acc = headers['access-control-allow-credentials'] || '';
  const acm = headers['access-control-allow-methods'] || '';
  const ach = headers['access-control-allow-headers'] || '';
  return `Origin: ${aco || 'None'}, Cred: ${acc || 'None'}, Methods: ${acm || 'None'}, Headers: ${ach || 'None'}`;
}

function summarizeCookies(cookies) {
  if (!cookies || !cookies.length) return 'None';
  return cookies.map(c =>
    `${c.name} [${c.sameSite || 'None'}${c.secure ? ', Secure' : ''}${c.httpOnly ? ', HttpOnly' : ''}]`
  ).join('; ');
}

function summarizeProtections(headers, cookies, forms) {
  const protections = [];
  if (headers['x-frame-options']) protections.push('X-Frame-Options');
  if (headers['content-security-policy']) protections.push('Content-Security-Policy');
  if (headers['access-control-allow-origin']) protections.push('CORS');
  if (headers['x-csrf-token'] || headers['x-xsrf-token'] || headers['x-requested-with']) protections.push('Custom CSRF Header');
  if (cookies.some(c => c.sameSite && c.sameSite !== 'None')) protections.push('SameSite Cookie');
  if (cookies.some(c => c.secure)) protections.push('Secure Cookie');
  if (cookies.some(c => c.httpOnly)) protections.push('HttpOnly Cookie');
  if (forms.some(f => f.tokens.length > 0)) protections.push('CSRF Token');
  return protections.length ? protections.join(', ') : 'None';
}

function extractFormsAndTokens(forms) {
  return forms.map(form => ({
    action: form.action,
    method: form.method,
    tokens: form.inputs.filter(i =>
      i.type === 'hidden' &&
      /(csrf|token|auth|secure|xsrf|nonce|key|secret)/i.test(i.name)
    ).map(i => i.name)
  }));
}

async function discoverLinksAndForms(page, baseUrl, maxLinks = 100) {
  // Returns { links: [...], apis: [...], forms: [...] }
  try {
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(1200);
    const { links, apis, forms } = await page.evaluate(() => {
      // Links
      const anchors = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
      // APIs (script src, fetch/ajax endpoints)
      const apis = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
      // Forms
      const forms = Array.from(document.forms).map(form => ({
        action: form.action || window.location.href,
        method: (form.method || 'GET').toUpperCase(),
        inputs: Array.from(form.elements).map(el => ({
          name: el.name,
          type: el.type,
          value: el.value
        }))
      }));
      return { links: anchors, apis, forms };
    });
    // Filter for same-origin and deduplicate
    const base = new URL(baseUrl);
    const allLinks = links.concat(apis)
      .map(l => {
        try { return new URL(l, base).toString(); } catch { return null; }
      })
      .filter(l => l && new URL(l).host === base.host)
      .slice(0, maxLinks);
    return { links: [...new Set(allLinks)], forms };
  } catch (e) {
    send('log', `[DISCOVER] Error crawling ${baseUrl}: ${e.message}`, 'error');
    return { links: [], forms: [] };
  }
}

async function testCorsAndCsrf(page, url, method, origin, opts, cookies, forms, headers) {
  let result = {
    method,
    origin,
    corsHeaders: '',
    status: '',
    evidence: '',
    type: '',
    endpoint: url,
    protections: '',
    cookies: '',
    forms: '',
    missingProtections: []
  };

  // Preflight (OPTIONS)
  let preflight = { status: 0, headers: {} };
  if (method !== 'GET') {
    try {
      preflight = await page.evaluate(async (url, origin, method) => {
        try {
          const resp = await fetch(url, {
            method: 'OPTIONS',
            headers: {
              'Origin': origin,
              'Access-Control-Request-Method': method,
              'Access-Control-Request-Headers': 'X-Test-Header'
            },
            credentials: 'include',
            mode: 'cors'
          });
          const headers = {};
          resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
          return { status: resp.status, headers };
        } catch (e) {
          return { status: 0, headers: {}, error: e.message };
        }
      }, url, origin, method);
    } catch (e) {
      send('log', `[PRE-FLIGHT] Error: ${e.message}`, 'error');
    }
  }

  // Actual request
  let res = { status: 0, headers: {}, body: '', error: null };
  try {
    res = await page.evaluate(async (url, origin, method) => {
      try {
        const resp = await fetch(url, {
          method,
          headers: { 'Origin': origin, 'X-Test-Header': 'cors-spider' },
          credentials: 'include',
          mode: 'cors'
        });
        const headers = {};
        resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        let body = '';
        try { body = await resp.text(); } catch {}
        return { status: resp.status, headers, body };
      } catch (e) {
        return { status: 0, headers: {}, body: '', error: e.message };
      }
    }, url, origin, method);
  } catch (e) {
    send('log', `[FETCH] Error: ${e.message}`, 'error');
  }

  // Cookie/CSRF/Protection analysis
  result.corsHeaders = summarizeCorsHeaders(res.headers);
  result.cookies = summarizeCookies(cookies);
  result.forms = JSON.stringify(forms);
  result.protections = summarizeProtections(res.headers, cookies, forms);

  // CORS detection logic
  const readable = !!res.body && res.body.length > 0;
  const credentialsAccepted = !!res.headers['access-control-allow-credentials'] && res.headers['access-control-allow-credentials'].toLowerCase() === 'true';

  if (res.headers['access-control-allow-origin'] === origin) {
    if (credentialsAccepted) {
      result.type = 'Critical CORS';
      result.status = 'Exploitable';
      result.evidence = 'Origin reflected and credentials allowed. Response readable: ' + (readable ? 'Yes' : 'No');
    } else {
      result.type = 'CORS Reflection';
      result.status = 'Potential';
      result.evidence = 'Origin reflected, credentials not allowed. Response readable: ' + (readable ? 'Yes' : 'No');
    }
  } else if (res.headers['access-control-allow-origin'] === '*') {
    if (credentialsAccepted) {
      result.type = 'Critical CORS';
      result.status = 'Exploitable';
      result.evidence = 'Wildcard origin with credentials allowed. Response readable: ' + (readable ? 'Yes' : 'No');
    } else {
      result.type = 'Wildcard CORS';
      result.status = 'Potential';
      result.evidence = 'Wildcard origin, credentials not allowed. Response readable: ' + (readable ? 'Yes' : 'No');
    }
  } else if (res.headers['access-control-allow-origin']) {
    result.type = 'CORS Present';
    result.status = 'Info';
    result.evidence = 'Access-Control-Allow-Origin: ' + res.headers['access-control-allow-origin'];
  } else {
    result.type = 'No CORS';
    result.status = 'Safe';
    result.evidence = 'No CORS headers returned.';
  }

  // Preflight analysis
  if (method !== 'GET' && preflight.status >= 200 && preflight.status < 400) {
    if (preflight.headers['access-control-allow-origin'] === origin) {
      result.evidence += ' Preflight allows origin.';
    }
    if (preflight.headers['access-control-allow-origin'] === '*') {
      result.evidence += ' Preflight allows wildcard.';
    }
  }

  // Sensitive endpoint
  if (isSensitiveEndpoint(url) && (result.status === 'Exploitable' || result.status === 'Potential')) {
    result.type = 'Sensitive ' + result.type;
    result.evidence += ' Endpoint appears sensitive.';
  }

  // If readable and credentials accepted, mark as critical
  if (readable && credentialsAccepted) {
    result.status = 'Exploitable';
    result.type = 'Critical CORS';
  }

  // CSRF protection checks
  const missing = [];
  if (!forms.some(f => f.tokens.length > 0)) missing.push('No CSRF Token');
  if (!cookies.some(c => c.sameSite && c.sameSite !== 'None')) missing.push('No SameSite Cookie');
  if (!cookies.some(c => c.secure)) missing.push('No Secure Cookie');
  if (!cookies.some(c => c.httpOnly)) missing.push('No HttpOnly Cookie');
  if (!res.headers['x-frame-options']) missing.push('No X-Frame-Options');
  if (!res.headers['content-security-policy']) missing.push('No CSP');
  if (!res.headers['x-csrf-token'] && !res.headers['x-xsrf-token'] && !res.headers['x-requested-with']) missing.push('No Custom CSRF Header');
  result.missingProtections = missing;

  // Report missing protections as findings
  if (missing.length) {
    send('finding', {
      type: 'Missing Protections',
      endpoint: url,
      method,
      origin,
      status: 'Warning',
      evidence: missing.join(', '),
      corsHeaders: result.corsHeaders,
      protections: result.protections
    });
  }

  // Always log the full result
  send('log', `[CORS/CSRF] [${result.type}] ${method} ${url} | Origin: ${origin} | Status: ${result.status} | Protections: ${result.protections} | Missing: ${missing.join(', ') || 'None'}`, result.status === 'Exploitable' ? 'warning' : (result.status === 'Potential' ? 'info' : 'debug'));

  // Report to frontend if exploitable or potential or missing protections
  if (result.status === 'Exploitable' || result.status === 'Potential' || missing.length) {
    send('finding', {
      type: result.type,
      endpoint: url,
      method,
      origin,
      corsHeaders: result.corsHeaders,
      status: result.status,
      evidence: result.evidence,
      protections: result.protections
    });
  }
}

async function spider(opts) {
  running = true;
  stopRequested = false;
  let progress = 0;
  let found = 0;
  const visited = new Set();
  const queue = [];
  const maxDepth = opts.depth || 3;
  const maxLinksPerPage = 50;
  const maxQueueSize = 2000;
  let errorCount = 0;
  let throttle = 100;

  // Start with user-supplied URLs
  for (const url of opts.urls) {
    queue.push({ url, depth: 0 });
  }

  send('log', `Scope: ${opts.urls.length} URLs. Starting CORS/CSRF spider...`, 'info');

  const browser = await puppeteer.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
      '--ignore-certificate-errors'
    ],
    ignoreHTTPSErrors: true,
    defaultViewport: { width: 1280, height: 900 }
  });
  const page = await browser.newPage();

  // Set up request/response logging for debugging
  page.on('request', req => send('log', `[REQ] ${req.method()} ${req.url()}`, 'http'));
  page.on('response', res => send('log', `[RES] ${res.status()} ${res.url()}`, 'http'));

  while (queue.length && !stopRequested) {
    if (queue.length > maxQueueSize) {
      send('log', `[QUEUE] Queue size exceeded (${queue.length}), trimming.`, 'warn');
      queue.splice(maxQueueSize);
    }
    const { url, depth } = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    progress++;
    send('progress', progress);
    send('log', `[SPIDER] Visiting: ${url} (depth=${depth})`, 'info');

    let navSuccess = false;
    let navError = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 35000 });
        navSuccess = true;
        break;
      } catch (e) {
        navError = e;
        send('log', `[RETRY] Navigation attempt ${attempt} failed for ${url}: ${e.message}`, 'warn');
        await sleep(500 * attempt);
      }
    }
    if (!navSuccess) {
      errorCount++;
      send('log', `[ERROR] Failed to visit ${url}: ${navError ? navError.message : 'Unknown error'} (errorCount=${errorCount})`, 'error');
      if (errorCount > 5) {
        throttle = Math.min(throttle + 250, 3000);
        send('log', `[THROTTLE] Increased delay to ${throttle}ms due to repeated errors.`, 'warn');
      }
      continue;
    }
    errorCount = 0;

    // Wait for dynamic content
    await page.waitForTimeout(1200);

    // Scroll to load lazy content
    await page.evaluate(async () => {
      await new Promise(resolve => {
        let totalHeight = 0;
        const distance = 200;
        const timer = setInterval(() => {
          window.scrollBy(0, distance);
          totalHeight += distance;
          if (totalHeight >= document.body.scrollHeight) {
            clearInterval(timer);
            resolve();
          }
        }, 100);
      });
    });

    // Get cookies and headers for analysis
    const cookies = await page.cookies();
    const headers = {}; // Not available directly, but can be improved with request interception if needed

    // Discover links, APIs, and forms
    const { links, forms } = await discoverLinksAndForms(page, url, maxLinksPerPage);
    const formsWithTokens = extractFormsAndTokens(forms);

    send('log', `[DISCOVER] Found ${links.length} links/APIs and ${forms.length} forms on ${url}`, 'info');

    // Test CORS/CSRF for this page and all discovered endpoints
    const endpoints = [url, ...links].slice(0, maxLinksPerPage);
    for (const endpoint of endpoints) {
      if (stopRequested) break;
      // Test with various origins and methods
      const originsToTest = [
        randomOrigin(),
        'https://evil.c0rs-spider.com',
        'https://sub.attacker.com',
        (new URL(endpoint)).origin
      ];
      const methods = ['GET', 'POST', 'PUT', 'DELETE'];
      for (const origin of originsToTest) {
        for (const method of methods) {
          send('log', `[TEST] ${method} ${endpoint} with Origin: ${origin}`, 'action');
          try {
            await testCorsAndCsrf(page, endpoint, method, origin, opts, cookies, formsWithTokens, headers);
          } catch (e) {
            send('log', `[ERROR] Testing ${endpoint}: ${e.message}`, 'error');
            continue;
          }
        }
      }
      if (stopRequested) break;
    }

    // Spider discovered links if depth allows
    if (depth < maxDepth) {
      for (const link of links) {
        if (!visited.has(link)) {
          queue.push({ url: link, depth: depth + 1 });
        }
      }
    }

    // Adaptive throttling
    if (errorCount === 0 && throttle > 100) {
      throttle = Math.max(throttle - 50, 100);
      send('log', `[THROTTLE] Decreased delay to ${throttle}ms (healthy)`, 'info');
    }
    await sleep(throttle);
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
