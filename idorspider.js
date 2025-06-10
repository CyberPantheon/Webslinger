// idorspider.js - IDOR Spider Engine
// Robust IDOR spider for Electron app
const { parentPort } = require('worker_threads');
const { fork, isMainThread, parent } = require('child_process');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const { parse: parseHtml } = require('./simple-html-parser');
const dns = require('dns').promises;
const fs = require('fs');

// Utility: sleep
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Enhanced test values for fuzzing
const COMMON_VALUES = [
    0, 1, 2, 9999, -1, 100, 123, 42, 1337, 1000, 10000, 2147483647,
    null, undefined, true, false,
    '', ' ', '\\', '/',
    '../../', '../', './',
    Buffer.from('admin').toString('base64'),
    '{{}}', '${7*7}', '<script>alert(1)</script>'
];

// Enhanced regex patterns
const ID_PATTERNS = {
    uuid: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    numeric: /\d+/g,
    base64: /[a-zA-Z0-9+/]{32,}/g,
    jwt: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g,
    hash: /[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}/gi
};

let running = false;
let discoveredIds = new Set();
let findings = [];
let cookies = '';

function send(type, data, extra) {
  if (process.send) process.send({ type, data, extra });
}

function log(msg, level = 'info') {
  send('log', msg, level);
}

function progress(val) {
  send('progress', val);
}

function found(count) {
  send('found', count);
}

function status(s) {
  send('status', s);
}

function addFinding(finding) {
  findings.push(finding);
  send('finding', finding);
  found(findings.length);
}

function extractIds(str) {
  const ids = new Set();
  let m;
  while ((m = ID_PATTERNS.numeric.exec(str))) ids.add(m[0]);
  while ((m = ID_PATTERNS.uuid.exec(str))) ids.add(m[0]);
  return Array.from(ids);
}

function extractLinks(html, baseUrl) {
  try {
    const root = parseHtml(html);
    const links = [];
    root.querySelectorAll('a[href]').forEach(a => {
      let href = a.getAttribute('href');
      if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;
      if (href.startsWith('/')) {
        const u = new URL(baseUrl);
        href = `${u.protocol}//${u.host}${href}`;
      } else if (!href.startsWith('http')) {
        const u = new URL(baseUrl);
        href = `${u.protocol}//${u.host}/${href}`;
      }
      links.push(href);
    });
    return Array.from(new Set(links));
  } catch (e) { return []; }
}

function extractForms(html, baseUrl) {
  try {
    const root = parseHtml(html);
    const forms = [];
    root.querySelectorAll('form').forEach(form => {
      const action = form.getAttribute('action') || baseUrl;
      const method = (form.getAttribute('method') || 'GET').toUpperCase();
      const inputs = [];
      form.querySelectorAll('input').forEach(input => {
        const name = input.getAttribute('name');
        if (name) inputs.push(name);
      });
      forms.push({ action, method, inputs });
    });
    return forms;
  } catch (e) { return []; }
}

// Rate limiting protection
class RateLimiter {
    constructor(maxRequests = 50, timeWindow = 1000) {
        this.queue = [];
        this.maxRequests = maxRequests;
        this.timeWindow = timeWindow;
    }

    async throttle() {
        const now = Date.now();
        this.queue = this.queue.filter(time => time > now - this.timeWindow);
        if (this.queue.length >= this.maxRequests) {
            await sleep(this.timeWindow);
        }
        this.queue.push(now);
    }
}

const rateLimiter = new RateLimiter();

// Enhanced fetch with retry and timeout
async function fetchUrl(url, opts = {}) {
    const maxRetries = opts.retries || 3;
    const timeout = opts.timeout || 10000;
    
    for (let i = 0; i < maxRetries; i++) {
        try {
            await rateLimiter.throttle();
            return await new Promise((resolve, reject) => {
                try {
                    const isHttps = url.startsWith('https://');
                    const mod = isHttps ? https : http;
                    const u = new URL(url);
                    const reqOpts = {
                        hostname: u.hostname,
                        port: u.port || (isHttps ? 443 : 80),
                        path: u.pathname + u.search,
                        method: opts.method || 'GET',
                        headers: opts.headers || {},
                    };
                    if (opts.cookies) reqOpts.headers['Cookie'] = opts.cookies;
                    let body = '';
                    const req = mod.request(reqOpts, res => {
                        res.on('data', chunk => { body += chunk; });
                        res.on('end', () => {
                          resolve({ status: res.statusCode, headers: res.headers, body });
                        });
                      });
                      req.on('error', reject);
                      if (opts.body) req.write(opts.body);
                      req.end();
                      
                      // Add timeout
                      req.setTimeout(timeout);
                      
                      // Enhanced headers
                      reqOpts.headers = {
                          ...reqOpts.headers,
                          'Accept': 'application/json, text/html, */*',
                          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                          'X-Requested-With': 'XMLHttpRequest'
                      };
                      
                      if (opts.json) {
                          reqOpts.headers['Content-Type'] = 'application/json';
                      }
                } catch (e) { reject(e); }
            });
        } catch (e) {
            if (i === maxRetries - 1) throw e;
            await sleep(1000 * Math.pow(2, i));
        }
    }
}

async function crawl(url, opts, depth, visited, parentIds = []) {
  if (!running || depth > opts.depthLimit || visited.has(url)) return;
  visited.add(url);
  log(`Crawling: ${url}`);
  let resp;
  try {
    resp = await fetchUrl(url, { cookies });
  } catch (e) {
    log(`Fetch failed: ${url} (${e.message})`, 'error');
    return;
  }
  progress(visited.size);
  // Extract IDs
  const ids = extractIds(resp.body);
  ids.forEach(id => discoveredIds.add(id));
  // Extract links and forms
  const links = extractLinks(resp.body, url);
  const forms = extractForms(resp.body, url);
  // Fuzz parameters in URL
  await fuzzUrlParams(url, resp, opts, parentIds);
  // Fuzz forms
  for (const form of forms) {
    await fuzzForm(form, url, opts, parentIds);
  }
  // Recurse
  for (const link of links) {
    await crawl(link, opts, depth + 1, visited, ids);
  }
  // Optionally: enumerate subdomains
  if (opts.enumSubdomains && depth === 0) {
    const subdomains = await enumerateSubdomains(url);
    for (const sub of subdomains) {
      await crawl(sub, opts, depth + 1, visited, ids);
    }
  }
}

async function fuzzUrlParams(url, origResp, opts, parentIds) {
  try {
    const u = new URL(url);
    for (const [key, value] of u.searchParams.entries()) {
      // Numeric fuzzing
      if (opts.fuzzNumeric && value.match(ID_PATTERNS.numeric)) {
        for (const v of COMMON_VALUES) {
          await testParam(u, key, v, origResp, opts, 'numeric-fuzz');
        }
      }
      // Known IDs
      if (opts.fuzzKnownIds) {
        for (const id of discoveredIds) {
          if (id !== value) await testParam(u, key, id, origResp, opts, 'known-id');
        }
      }
      // Swap with parent IDs
      for (const pid of parentIds) {
        if (pid !== value) await testParam(u, key, pid, origResp, opts, 'parent-id');
      }
    }
  } catch (e) { log('fuzzUrlParams error: ' + e.message, 'error'); }
}

async function testParam(u, key, newValue, origResp, opts, technique) {
  const testUrl = new URL(u.toString());
  testUrl.searchParams.set(key, newValue);
  let testCookies = cookies;
  if (opts.noCookies) testCookies = '';
  let testResp;
  try {
    testResp = await fetchUrl(testUrl.toString(), { cookies: testCookies });
  } catch (e) {
    log(`Test failed: ${testUrl} (${e.message})`, 'error');
    return;
  }
  if (isPotentialIdor(origResp, testResp)) {
    addFinding({
      endpoint: testUrl.toString(),
      parameter: key,
      payload: newValue,
      technique,
      evidence: summarizeDiff(origResp, testResp),
      status: 'Potential IDOR',
      type: 'URL',
    });
  }
}

async function fuzzForm(form, baseUrl, opts, parentIds) {
  // Only fuzz GET/POST forms
  for (const param of form.inputs) {
    // Numeric fuzzing
    if (opts.fuzzNumeric) {
      for (const v of COMMON_VALUES) {
        await testForm(form, baseUrl, param, v, opts, 'numeric-fuzz');
      }
    }
    // Known IDs
    if (opts.fuzzKnownIds) {
      for (const id of discoveredIds) {
        await testForm(form, baseUrl, param, id, opts, 'known-id');
      }
    }
    // Swap with parent IDs
    for (const pid of parentIds) {
      await testForm(form, baseUrl, param, pid, opts, 'parent-id');
    }
  }
}

async function testForm(form, baseUrl, param, value, opts, technique) {
  const u = new URL(form.action, baseUrl);
  let params = {};
  form.inputs.forEach(i => { params[i] = i === param ? value : 'test'; });
  let testCookies = cookies;
  if (opts.noCookies) testCookies = '';
  let resp;
  try {
    if (form.method === 'GET') {
      Object.entries(params).forEach(([k, v]) => u.searchParams.set(k, v));
      resp = await fetchUrl(u.toString(), { cookies: testCookies });
    } else {
      resp = await fetchUrl(u.toString(), {
        method: 'POST',
        body: new URLSearchParams(params).toString(),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        cookies: testCookies,
      });
    }
  } catch (e) {
    log(`Form test failed: ${u} (${e.message})`, 'error');
    return;
  }
  // Compare with original (not always possible)
  if (isPotentialIdor(null, resp)) {
    addFinding({
      endpoint: u.toString(),
      parameter: param,
      payload: value,
      technique,
      evidence: 'Form submission triggered interesting response',
      status: 'Potential IDOR',
      type: 'FORM',
    });
  }
}

function isPotentialIdor(orig, test) {
  // Heuristic: status code change, content change, or access denied/allowed
  if (!test) return false;
  if (orig && test.status !== orig.status) return true;
  if (test.body && orig && test.body !== orig.body) {
    if (/access denied|not authorized|forbidden|error/i.test(test.body)) return false;
    return true;
  }
  if (test.body && /success|user|admin|flag|token|id|confidential/i.test(test.body)) return true;
  return false;
}

function summarizeDiff(orig, test) {
  if (!orig) return `Response: ${test.status}`;
  if (orig.status !== test.status) return `Status changed: ${orig.status} -> ${test.status}`;
  if (orig.body && test.body && orig.body !== test.body) {
    return `Body changed (${orig.body.length} -> ${test.body.length})`;
  }
  return 'See response.';
}

async function analyzeResponse(orig, test) {
    // Enhanced response analysis
    const indicators = {
        sensitiveData: /(password|ssn|credit.?card|secret|token)/i,
        personalInfo: /(email|phone|address|birth.?date)/i,
        errors: /(exception|error|stack.?trace|syntax)/i,
        success: /(success|welcome|logged.?in)/i
    };

    const changes = {
        status: test.status !== orig?.status,
        length: test.body?.length !== orig?.body?.length,
        contentType: test.headers?.['content-type'] !== orig?.headers?.['content-type'],
        sensitiveData: Object.entries(indicators)
            .filter(([_, regex]) => regex.test(test.body))
            .map(([key]) => key)
    };

    return {
        suspicious: changes.sensitiveData.length > 0 || changes.status,
        changes
    };
}

// Add parallel execution support
async function parallelCrawl(urls, opts, maxConcurrency = 5) {
    const queue = [...urls];
    const active = new Set();
    const results = [];

    while (queue.length > 0 || active.size > 0) {
        while (queue.length > 0 && active.size < maxConcurrency) {
            const url = queue.shift();
            const promise = crawl(url, opts, 0, new Set())
                .then(result => {
                    active.delete(promise);
                    results.push(result);
                });
            active.add(promise);
        }
        await Promise.race([...active]);
    }

    return results;
}

async function enumerateSubdomains(url) {
  // Very basic: try common subdomains
  const common = ['www', 'dev', 'test', 'admin', 'api', 'staging', 'beta', 'user', 'portal'];
  const u = new URL(url);
  const found = [];
  for (const sub of common) {
    const host = `${sub}.${u.hostname}`;
    try {
      await dns.resolve4(host);
      found.push(`${u.protocol}//${host}${u.pathname}`);
    } catch (e) {}
  }
  return found;
}

async function main(opts) {
  running = true;
  findings = [];
  discoveredIds = new Set();
  cookies = opts.cookies || '';
  status('Running');
  try {
    await crawl(opts.url, opts, 0, new Set());
  } catch (e) {
    log('Fatal error: ' + e.message, 'error');
  }
  status('Idle');
  running = false;
}

process.on('message', async msg => {
  if (msg.type === 'start') {
    main(msg.data);
  } else if (msg.type === 'stop') {
    running = false;
    status('Stopped');
    process.exit(0);
  }
});

// For direct CLI testing
if (require.main === module) {
  const url = process.argv[2];
  if (!url) return console.log('Usage: node idorspider.js <url>');
  main({ url, depthLimit: 2, fuzzNumeric: true, fuzzKnownIds: true, noCookies: false, enumSubdomains: false });
}
