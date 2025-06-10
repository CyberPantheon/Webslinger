console.log('[OpenRedirectSpider] openredirectspider.js loaded and running');

const { parentPort } = require('worker_threads');
const { URL } = require('url');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

let running = false;
let stopRequested = false;

function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Expanded and fuzzy matching for redirect params
function isLikelyRedirectParam(param) {
  const names = [
    'url', 'redirect', 'next', 'target', 'dest', 'destination', 'redir', 'return', 'returnto', 'goto', 'out', 'continue', 'forward', 'to', 'u', 'link', 'jump', 'navigate', 'path', 'ref', 'referrer', 'callback', 'back', 'return_url', 'redirect_url', 'redirect_uri', 'returnuri', 'returl', 'returnpath'
  ];
  param = param.toLowerCase();
  return names.some(n => param.includes(n) || param.replace(/[^a-z]/g, '') === n);
}

function extractParamsFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return Array.from(u.searchParams.keys());
  } catch {
    return [];
  }
}

// Extract links from <a>, <form>, <meta http-equiv="refresh">, JS, etc.
function getAllLinks(html, baseUrl) {
  const links = new Set();
  // <a href="">
  const aRegex = /<a\s+[^>]*href=["']([^"']+)["']/gi;
  let match;
  while ((match = aRegex.exec(html))) {
    let href = match[1];
    if (!href.startsWith('http')) {
      try {
        const base = new URL(baseUrl);
        if (href.startsWith('/')) {
          href = `${base.protocol}//${base.host}${href}`;
        } else {
          href = `${base.protocol}//${base.host}/${href}`;
        }
      } catch {}
    }
    links.add(href);
  }
  // <form action="">
  const formRegex = /<form\s+[^>]*action=["']([^"']+)["']/gi;
  while ((match = formRegex.exec(html))) {
    let href = match[1];
    if (!href.startsWith('http')) {
      try {
        const base = new URL(baseUrl);
        if (href.startsWith('/')) {
          href = `${base.protocol}//${base.host}${href}`;
        } else {
          href = `${base.protocol}//${base.host}/${href}`;
        }
      } catch {}
    }
    links.add(href);
  }
  // <meta http-equiv="refresh" content="0;url=...">
  const metaRegex = /<meta\s+http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"'>]+)["']/gi;
  while ((match = metaRegex.exec(html))) {
    let href = match[1];
    if (!href.startsWith('http')) {
      try {
        const base = new URL(baseUrl);
        if (href.startsWith('/')) {
          href = `${base.protocol}//${base.host}${href}`;
        } else {
          href = `${base.protocol}//${base.host}/${href}`;
        }
      } catch {}
    }
    links.add(href);
  }
  // JS-based window.location, location.href, etc.
  const jsRegex = /location\.(?:href|replace|assign)\s*=\s*['"]([^'"]+)['"]/gi;
  while ((match = jsRegex.exec(html))) {
    let href = match[1];
    if (!href.startsWith('http')) {
      try {
        const base = new URL(baseUrl);
        if (href.startsWith('/')) {
          href = `${base.protocol}//${base.host}${href}`;
        } else {
          href = `${base.protocol}//${base.host}/${href}`;
        }
      } catch {}
    }
    links.add(href);
  }
  return Array.from(links);
}

// Randomize user-agent for stealth
function getRandomUserAgent() {
  const agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
  ];
  return agents[Math.floor(Math.random() * agents.length)];
}

// Request with redirect chain following, detailed logging, and adaptive throttling
async function requestUrl(url, method = 'GET', headers = {}, body = null, timeout = 20000, maxRedirects = 5, maxRetries = 3) {
  let redirects = [];
  let currentUrl = url;
  let resp, lastResp;
  let redirectCount = 0;
  let attempt = 0;
  let lastError = null;
  while (attempt < maxRetries) {
    try {
      while (redirectCount <= maxRedirects) {
        try {
          const urlObj = new URL(currentUrl);
          const isHttps = urlObj.protocol === 'https:';
          const options = {
            method,
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: urlObj.pathname + urlObj.search,
            headers: Object.assign({
              'User-Agent': getRandomUserAgent(),
              'Accept': '*/*',
            }, headers),
            timeout: timeout,
            rejectUnauthorized: false,
          };
          send('log', `[HTTP] ${method} ${currentUrl} (timeout=${timeout}ms)`, 'http');
          resp = await new Promise((resolve, reject) => {
            const req = (isHttps ? https : http).request(options, (res) => {
              let data = '';
              res.on('data', (chunk) => { data += chunk.toString(); });
              res.on('end', () => {
                resolve({
                  statusCode: res.statusCode,
                  headers: res.headers,
                  body: data,
                  redirected: [301, 302, 303, 307, 308].includes(res.statusCode),
                  location: res.headers.location,
                  url: currentUrl,
                  cookies: res.headers['set-cookie'] || [],
                });
              });
            });
            req.on('error', reject);
            if (body) req.write(body);
            req.end();
          });
          lastResp = resp;
          if (resp.redirected && resp.location) {
            send('log', `[REDIRECT] ${currentUrl} -> ${resp.location} (${resp.statusCode})`, 'redirect');
            redirects.push({ url: currentUrl, status: resp.statusCode, location: resp.location });
            // Absolute or relative redirect
            if (/^https?:\/\//i.test(resp.location)) {
              currentUrl = resp.location;
            } else if (resp.location.startsWith('/')) {
              const base = new URL(currentUrl);
              currentUrl = `${base.protocol}//${base.host}${resp.location}`;
            } else {
              // Relative path
              const base = new URL(currentUrl);
              currentUrl = `${base.protocol}//${base.host}/${resp.location}`;
            }
            redirectCount++;
            continue;
          }
          break;
        } catch (e) {
          lastError = e;
          attempt++;
          send('log', `[RETRY] Attempt ${attempt} failed for ${currentUrl}: ${e.message}`, 'warn');
          await sleep(500 * attempt); // Exponential backoff
        }
      }
      if (redirects.length) {
        lastResp.redirectChain = redirects;
      }
      return lastResp;
    } catch (e) {
      lastError = e;
      attempt++;
      send('log', `[RETRY] Attempt ${attempt} failed for ${currentUrl}: ${e.message}`, 'warn');
      await sleep(500 * attempt); // Exponential backoff
    }
  }
  send('log', `[ERROR] All ${maxRetries} attempts failed for ${currentUrl}: ${lastError ? lastError.message : 'Unknown error'}`, 'error');
  throw lastError || new Error('Unknown request error');
}

// Generate a unique hash for a finding to avoid duplicates
function findingHash(obj) {
  return crypto.createHash('sha1').update(JSON.stringify(obj)).digest('hex');
}

// Payloads for open redirect fuzzing
const payloads = [
  'https://evil.com',
  '//evil.com',
  '/\\evil.com',
  '///evil.com',
  'https://evil.com/%2e%2e',
  'https://evil.com/%2f',
  'https://evil.com/%5c',
  'https://evil.com/%09',
  'https://evil.com/%00',
  'https://evil.com#@legit.com',
  'https://evil.com?@legit.com',
  'javascript://evil.com',
  '///evil.com/%2e%2e',
  'https://evil.com%2f..',
  'https://evil.com%5c..',
  'https://evil.com%2e%2e%2f',
  'https://evil.com%2e%2e%5c',
  'https://evil.com/%252e%252e',
  'https://evil.com/%2e%2e%2f',
  'https://evil.com/%2e%2e%5c',
  'https://evil.com/%5c%5c',
  'https://evil.com/%2f%2f',
  'https://evil.com/%5c%2f',
  'https://evil.com/%2f%5c',
  'https://evil.com/%2e%2e%2f%2e%2e%2f',
  'https://evil.com/%2e%2e%5c%2e%2e%5c',
  'https://evil.com/%2e%2e/%2e%2e/',
  'https://evil.com/%2e%2e\\%2e%2e\\',
  'https://evil.com/%40evil.com',
  'https://evil.com%40evil.com',
  'https://evil.com%23@legit.com',
  'https://evil.com%3F@legit.com',
  'https://evil.com%2F%40evil.com',
  'https://evil.com%2F%23@legit.com',
  'https://evil.com%2F%3F@legit.com',
  'https://evil.com%2F%2Flegit.com',
  'https://evil.com%2F%2F%2Flegit.com',
  'https://evil.com%2F%2F%2F%2Flegit.com',
  'https://evil.com%2F%2F%2F%2F%2Flegit.com',
  'https://evil.com/%252e%252e%252f',
  'https://evil.com/%252e%252e%255c',
  'https://evil.com/%252f%2540evil.com',
  'https://evil.com/%2523@legit.com',
  'https://evil.com/%253f@legit.com',
];

// Analyze response for open redirect evidence
function analyzeOpenRedirect({ url, param, payload, resp, origUrl, method, requestType }) {
  let findings = [];
  // 1. HTTP redirect
  if (resp.redirected && resp.location) {
    if (
      /evil\.com/i.test(resp.location) ||
      resp.location.startsWith('http://evil.com') ||
      resp.location.startsWith('https://evil.com') ||
      resp.location.startsWith('//evil.com')
    ) {
      findings.push({
        type: 'Open Redirect',
        endpoint: origUrl,
        parameter: param,
        payload: payload,
        method,
        requestType,
        status: 'Redirected',
        evidence: `Location: ${resp.location}`,
        redirectChain: resp.redirectChain || [],
        urlTested: url,
      });
    }
  }
  // 2. Meta refresh
  const metaMatch = resp.body && resp.body.match(/<meta\s+http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"'>]+)["']/i);
  if (metaMatch && /evil\.com/i.test(metaMatch[1])) {
    findings.push({
      type: 'Open Redirect (Meta Refresh)',
      endpoint: origUrl,
      parameter: param,
      payload: payload,
      method,
      requestType,
      status: 'Meta Refresh',
      evidence: `Meta refresh to: ${metaMatch[1]}`,
      urlTested: url,
    });
  }
  // 3. JS-based redirect
  if (
    /location\.(?:href|replace|assign)\s*=\s*['"]https?:\/\/evil\.com/i.test(resp.body) ||
    /window\.location\s*=\s*['"]https?:\/\/evil\.com/i.test(resp.body)
  ) {
    findings.push({
      type: 'Open Redirect (JS)',
      endpoint: origUrl,
      parameter: param,
      payload: payload,
      method,
      requestType,
      status: 'JS Redirect',
      evidence: 'JS-based redirect found in response body',
      urlTested: url,
    });
  }
  // 4. Reflected payload
  if (resp.body && resp.body.includes(payload)) {
    findings.push({
      type: 'Potential Open Redirect (Reflected)',
      endpoint: origUrl,
      parameter: param,
      payload: payload,
      method,
      requestType,
      status: 'Reflected',
      evidence: 'Payload reflected in response body',
      urlTested: url,
    });
  }
  // 5. Cookie-based redirect
  if (resp.cookies && resp.cookies.some(c => /evil\.com/i.test(c))) {
    findings.push({
      type: 'Open Redirect (Cookie)',
      endpoint: origUrl,
      parameter: param,
      payload: payload,
      method,
      requestType,
      status: 'Cookie',
      evidence: `Set-Cookie: ${resp.cookies.join('; ')}`,
      urlTested: url,
    });
  }
  return findings;
}

// Main spider function
async function spider(opts) {
  running = true;
  stopRequested = false;
  let progress = 0;
  let found = 0;
  const reported = new Set();
  const queue = [];
  const visited = new Set();
  const domainVisited = new Set();
  let errorCount = 0;
  let throttle = 50;

  // 1. Crawl user-supplied URLs first (in order)
  for (const url of opts.urls) {
    queue.push({ url, depth: 0, phase: 'scope' });
  }

  send('log', `Scope: ${opts.urls.length} URLs. Starting spider...`, 'info');

  while (queue.length && !stopRequested) {
    const { url, depth, phase } = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    progress++;
    send('progress', progress);
    send('log', `[SPIDER] (${phase}) Fetching: ${url} (depth=${depth})`, 'info');

    let resp;
    try {
      resp = await requestUrl(url, 'GET', {}, null, 20000, 5, 3); // Increased timeout and retries
      errorCount = 0;
    } catch (e) {
      errorCount++;
      send('log', `[ERROR] Failed to fetch ${url}: ${e.message} (errorCount=${errorCount})`, 'error');
      if (errorCount > 5) {
        throttle = Math.min(throttle + 250, 2000);
        send('log', `[THROTTLE] Increased delay to ${throttle}ms due to repeated errors.`, 'warn');
      }
      continue;
    }

    // 2. Analyze for open redirect params in this URL (GET)
    const params = extractParamsFromUrl(url);
    for (const param of params) {
      if (!isLikelyRedirectParam(param)) continue;
      for (const payload of payloads) {
        if (stopRequested) break;
        let testUrl;
        try {
          const u = new URL(url);
          u.searchParams.set(param, payload);
          testUrl = u.toString();
        } catch { continue; }
        send('log', `[FUZZ] Testing param "${param}" with payload "${payload}" (GET)`, 'action');
        let testResp;
        try {
          testResp = await requestUrl(testUrl, 'GET', {}, null, 10000, 5);
        } catch (e) {
          send('log', `[ERROR] Error testing ${testUrl}: ${e.message}`, 'error');
          continue;
        }
        const findings = analyzeOpenRedirect({
          url: testUrl,
          param,
          payload,
          resp: testResp,
          origUrl: url,
          method: 'GET',
          requestType: 'query'
        });
        for (const finding of findings) {
          const hash = findingHash(finding);
          if (!reported.has(hash)) {
            found++;
            send('found', found);
            send('finding', finding);
            reported.add(hash);
            send('log', `[FINDING] ${JSON.stringify(finding)}`, 'finding');
          }
        }
      }
    }

    // 3. Analyze for open redirect params in forms (POST)
    const formRegex = /<form\s+[^>]*action=["']([^"']+)["'][^>]*>/gi;
    let match;
    while ((match = formRegex.exec(resp.body))) {
      let action = match[1];
      let formUrl = action.startsWith('http') ? action : (() => {
        try {
          const base = new URL(url);
          if (action.startsWith('/')) {
            return `${base.protocol}//${base.host}${action}`;
          } else {
            return `${base.protocol}//${base.host}/${action}`;
          }
        } catch { return url; }
      })();
      // Try fuzzing likely redirect params in POST body
      const inputRegex = /<input\s+[^>]*name=["']([^"']+)["'][^>]*>/gi;
      let inputMatch;
      let paramsToTest = [];
      while ((inputMatch = inputRegex.exec(resp.body))) {
        if (isLikelyRedirectParam(inputMatch[1])) {
          paramsToTest.push(inputMatch[1]);
        }
      }
      for (const param of paramsToTest) {
        for (const payload of payloads) {
          if (stopRequested) break;
          const postData = `${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;
          send('log', `[FUZZ] Testing form param "${param}" with payload "${payload}" (POST to ${formUrl})`, 'action');
          let testResp;
          try {
            testResp = await requestUrl(formUrl, 'POST', {
              'Content-Type': 'application/x-www-form-urlencoded'
            }, postData, 10000, 5);
          } catch (e) {
            send('log', `[ERROR] Error testing POST ${formUrl}: ${e.message}`, 'error');
            continue;
          }
          const findings = analyzeOpenRedirect({
            url: formUrl,
            param,
            payload,
            resp: testResp,
            origUrl: url,
            method: 'POST',
            requestType: 'form'
          });
          for (const finding of findings) {
            const hash = findingHash(finding);
            if (!reported.has(hash)) {
              found++;
              send('found', found);
              send('finding', finding);
              reported.add(hash);
              send('log', `[FINDING] ${JSON.stringify(finding)}`, 'finding');
            }
          }
        }
      }
    }

    // 4. Spider links if depth allows, and only after scope URLs are crawled
    if (depth < (opts.depth || 3)) {
      const links = getAllLinks(resp.body, url);
      send('log', `[DISCOVER] Found ${links.length} links on ${url}`, 'info');
      for (const link of links) {
        if (visited.has(link)) continue;
        if (opts.sameDomain) {
          try {
            const baseHost = new URL(url).hostname;
            const linkHost = new URL(link).hostname;
            if (baseHost !== linkHost) continue;
          } catch { continue; }
        }
        // Avoid crawling the same domain path repeatedly
        const domainKey = (() => {
          try {
            const u = new URL(link);
            return u.hostname + u.pathname;
          } catch { return link; }
        })();
        if (domainVisited.has(domainKey)) continue;
        domainVisited.add(domainKey);
        queue.push({ url: link, depth: depth + 1, phase: 'spider' });
      }
    }

    // Adaptive throttling
    if (errorCount === 0 && throttle > 50) {
      throttle = Math.max(throttle - 50, 50);
      send('log', `[THROTTLE] Decreased delay to ${throttle}ms (healthy)`, 'info');
    }
    await sleep(throttle);
  }

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
