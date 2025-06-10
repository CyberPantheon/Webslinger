const puppeteer = require('puppeteer');

let running = false;
let stopRequested = false;

function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Expanded iframe modes for thoroughness
const IFRAME_MODES = [
  { name: 'No Sandbox', attr: '' },
  { name: 'allow-scripts', attr: 'sandbox="allow-scripts"' },
  { name: 'allow-forms allow-scripts', attr: 'sandbox="allow-forms allow-scripts"' },
  { name: 'allow-same-origin allow-scripts', attr: 'sandbox="allow-same-origin allow-scripts"' },
  { name: 'allow-top-navigation', attr: 'sandbox="allow-top-navigation"' },
  { name: 'allow-popups', attr: 'sandbox="allow-popups"' },
  { name: 'allow-forms allow-scripts allow-same-origin', attr: 'sandbox="allow-forms allow-scripts allow-same-origin"' },
  { name: 'allowfullscreen', attr: 'allowfullscreen' }
];

// Helper to summarize all relevant headers
function summarizeHeaders(headers) {
  const xfo = headers['x-frame-options'] || headers['X-Frame-Options'] || '';
  const csp = headers['content-security-policy'] || headers['Content-Security-Policy'] || '';
  const permissions = headers['permissions-policy'] || '';
  return `XFO: ${xfo || 'None'}, CSP: ${csp || 'None'}, Permissions-Policy: ${permissions || 'None'}`;
}

// Helper to check for sensitive URLs
function isSensitiveUrl(url) {
  return /(login|account|settings|delete|update|admin|user|profile|bank|fund|transfer|password|secure|checkout|cart|payment|pay|order|purchase)/i.test(url);
}

// Helper to check for clickjacking protections in headers
function checkProtections(headers) {
  const xfo = headers['x-frame-options'] || headers['X-Frame-Options'] || '';
  const csp = headers['content-security-policy'] || headers['Content-Security-Policy'] || '';
  let protections = [];
  if (xfo) protections.push(`X-Frame-Options: ${xfo}`);
  if (csp && /frame-ancestors/i.test(csp)) protections.push(`CSP frame-ancestors: ${csp}`);
  if (headers['permissions-policy']) protections.push(`Permissions-Policy: ${headers['permissions-policy']}`);
  return protections.length ? protections.join('; ') : 'None';
}

// Helper to extract all links from a page
async function extractLinks(page) {
  try {
    return await page.evaluate(() =>
      Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.href)
        .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('#'))
    );
  } catch {
    return [];
  }
}

// Main test function for a single iframe mode
async function testIframe(page, url, mode, opts) {
  let result = {
    iframeMode: mode.name,
    embeddable: false,
    clickRegistered: false,
    headers: '',
    status: '',
    evidence: '',
    sensitive: isSensitiveUrl(url),
    protections: '',
    jsErrors: [],
    frameBusting: false,
    overlayDetected: false,
    navigationBlocked: false
  };

  // Open a blank page and inject an iframe
  try {
    await page.goto('about:blank', { timeout: 30000, waitUntil: 'domcontentloaded' });
    send('log', `[ACTION] Navigated to about:blank for iframe injection.`, 'debug');
  } catch (e) {
    result.type = 'Error';
    result.status = 'Error';
    result.evidence = 'Failed to load about:blank: ' + e.message;
    send('log', `[ERROR] Failed to load about:blank: ${e.message}`, 'error');
    return result;
  }
  await page.setViewport({ width: 1200, height: 800 });

  // Intercept headers for the iframe request
  let responseHeaders = {};
  let navigationBlocked = false;
  page.on('response', resp => {
    if (resp.url() === url) {
      responseHeaders = resp.headers();
      send('log', `[HTTP] [RES] ${resp.status()} ${resp.url()} Headers: ${JSON.stringify(responseHeaders)}`, 'http');
    }
  });
  page.on('requestfailed', req => {
    if (req.url() === url) {
      navigationBlocked = true;
      send('log', `[HTTP] [REQ FAILED] ${req.url()} Reason: ${req.failure()?.errorText}`, 'warn');
    }
  });

  // Listen for JS errors
  let jsErrors = [];
  page.on('pageerror', err => {
    jsErrors.push(err.message);
    send('log', `[JS ERROR] ${err.message}`, 'error');
  });

  // Try to embed the target URL in an iframe
  let iframeLoaded = false;
  let frame = null;
  let frameBusting = false;
  let overlayDetected = false;
  try {
    send('log', `[ACTION] Injecting iframe for ${url} with mode: ${mode.name}`, 'action');
    await page.setContent(`
      <iframe id="testframe" src="${url}" width="900" height="600" ${mode.attr}></iframe>
      <script>
        window.iframeLoaded = false;
        document.getElementById('testframe').addEventListener('load', function() {
          window.iframeLoaded = true;
        });
      </script>
    `);
    // Wait for iframe to load or error
    await page.waitForFunction('window.iframeLoaded === true', { timeout: 20000 });
    iframeLoaded = true;
    send('log', `[ACTION] Iframe loaded for ${url} (${mode.name})`, 'debug');
  } catch (e) {
    iframeLoaded = false;
    result.type = 'Error';
    result.status = 'Error';
    result.evidence = 'Failed to load iframe: ' + e.message;
    send('log', `[ERROR] Failed to load iframe for ${url} (${mode.name}): ${e.message}`, 'error');
    return result;
  }

  // Try to access the iframe's contentWindow (detect frame busting)
  try {
    frame = await page.$('#testframe');
    const frameHandle = await frame.contentFrame();
    if (frameHandle) {
      // Try to run a script in the iframe context
      const isTop = await frameHandle.evaluate(() => window.top === window.self);
      if (!isTop) {
        frameBusting = true;
        send('log', `[INFO] Frame busting detected (window.top !== window.self) for ${url}`, 'info');
      }
      // Try to detect overlays (common clickjacking defense)
      overlayDetected = await frameHandle.evaluate(() => {
        const overlays = Array.from(document.querySelectorAll('*')).filter(el =>
          getComputedStyle(el).position === 'fixed' && parseFloat(getComputedStyle(el).zIndex) > 1000
        );
        return overlays.length > 0;
      });
      if (overlayDetected) {
        send('log', `[INFO] Overlay detected in iframe for ${url}`, 'info');
      }
    }
  } catch (e) {
    frameBusting = true;
    send('log', `[INFO] Frame busting JS exception for ${url}: ${e.message}`, 'info');
  }

  // Simulate a click inside the iframe if loaded
  let clickResult = '';
  if (iframeLoaded && frame) {
    try {
      const frameHandle = await frame.contentFrame();
      if (frameHandle) {
        // Try to click the center of the iframe
        await page.mouse.move(450, 300);
        await page.mouse.click(450, 300, { delay: 100 });
        // Try to detect if click was registered (e.g., by setting a variable in iframe)
        await frameHandle.evaluate(() => {
          window.__clickjackingTest = false;
          document.body.addEventListener('click', () => { window.__clickjackingTest = true; });
        });
        await page.mouse.click(450, 300, { delay: 100 });
        const clicked = await frameHandle.evaluate(() => window.__clickjackingTest);
        if (clicked) {
          result.clickRegistered = true;
          clickResult = 'Click registered inside iframe.';
          send('log', `[ACTION] Click registered inside iframe for ${url}`, 'debug');
        } else {
          clickResult = 'Click not registered or not observable.';
          send('log', `[ACTION] Click not registered in iframe for ${url}`, 'debug');
        }
      }
    } catch (e) {
      clickResult = 'Click simulation failed: ' + e.message;
      send('log', `[ERROR] Click simulation failed for ${url}: ${e.message}`, 'error');
    }
  }

  // Summarize headers and protections
  result.headers = summarizeHeaders(responseHeaders);
  result.protections = checkProtections(responseHeaders);
  result.jsErrors = jsErrors;
  result.frameBusting = frameBusting;
  result.overlayDetected = overlayDetected;
  result.navigationBlocked = navigationBlocked;

  // Detection logic
  if (iframeLoaded && !frameBusting && !navigationBlocked) {
    result.embeddable = true;
    if (result.clickRegistered) {
      result.type = result.sensitive ? 'Critical Clickjacking' : 'Clickjacking';
      result.status = 'Vulnerable';
      result.evidence = 'Page loads in iframe and accepts user interaction. ' + clickResult;
    } else {
      result.type = 'Embeddable';
      result.status = 'Potential';
      result.evidence = 'Page loads in iframe but click not observed. ' + clickResult;
    }
  } else {
    result.type = 'Protected';
    result.status = 'Protected';
    if (jsErrors.length) {
      result.evidence = 'JS error(s): ' + jsErrors.join('; ');
    } else if (frameBusting) {
      result.evidence = 'Frame busting detected (window.top !== window.self).';
    } else if (navigationBlocked) {
      result.evidence = 'Navigation to iframe was blocked (likely XFO/CSP).';
    } else {
      result.evidence = 'Page could not be loaded in iframe (likely XFO/CSP).';
    }
  }

  // Highlight missing/misconfigured headers
  if (result.embeddable) {
    if (!/deny|sameorigin/i.test(result.headers) && !/frame-ancestors/i.test(result.headers)) {
      result.evidence += ' Missing or weak X-Frame-Options/CSP headers.';
      send('log', `[WARNING] Missing or weak X-Frame-Options/CSP for ${url}`, 'warning');
    }
  } else if (result.status === 'Protected') {
    if (!result.protections || result.protections === 'None') {
      result.evidence += ' No explicit clickjacking protection headers found.';
      send('log', `[WARNING] No explicit clickjacking protection headers for ${url}`, 'warning');
    }
  }

  return result;
}

async function spider(opts) {
  running = true;
  stopRequested = false;
  let progress = 0;
  let found = 0;
  const visited = new Set();
  const queue = [];
  let errorCount = 0;
  let throttle = 100;
  let maxRetries = 3;
  let navigationTimeout = 35000;

  // Crawl user-supplied URLs first
  for (const url of opts.urls) {
    queue.push({ url, depth: 0, phase: 'scope' });
  }

  send('log', `[SPIDER] Scope: ${opts.urls.length} URLs. Starting Clickjacking spider...`, 'info');

  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage'], ignoreHTTPSErrors: true, defaultViewport: { width: 1280, height: 900 } });
  const page = await browser.newPage();

  // Set up request/response logging for debugging
  page.on('request', req => send('log', `[HTTP] [REQ] ${req.method()} ${req.url()}`, 'http'));
  page.on('response', res => send('log', `[HTTP] [RES] ${res.status()} ${res.url()}`, 'http'));

  while (queue.length && !stopRequested) {
    const { url, depth, phase } = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    progress++;
    send('progress', progress);

    send('log', `[SPIDER] (${phase}) Visiting: ${url} (depth=${depth})`, 'info');

    // Test all iframe modes for this URL
    for (const mode of IFRAME_MODES) {
      if (stopRequested) break;
      send('log', `[ACTION] Testing iframe mode: ${mode.name} for ${url}`, 'action');
      let result;
      try {
        result = await testIframe(page, url, mode, opts);
      } catch (e) {
        send('log', `[ERROR] Error testing iframe mode ${mode.name} for ${url}: ${e.message}`, 'error');
        continue;
      }
      // Report finding to frontend
      send('finding', {
        type: result.type,
        endpoint: url,
        iframeMode: result.iframeMode,
        headers: result.headers,
        protections: result.protections,
        status: result.status,
        evidence: result.evidence,
        jsErrors: result.jsErrors,
        overlayDetected: result.overlayDetected,
        frameBusting: result.frameBusting,
        navigationBlocked: result.navigationBlocked
      });
      if (result.status === 'Vulnerable' || result.status === 'Potential') {
        found++;
        send('found', found);
        send('log', `[FINDING] Clickjacking issue detected: ${url} (${result.status}) [${result.iframeMode}]`, 'warning');
      }
    }

    // Spider links if depth allows
    if (depth < (opts.depth || 2)) {
      let links = [];
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: navigationTimeout });
        links = await extractLinks(page);
        send('log', `[DISCOVER] Found ${links.length} links on ${url}`, 'info');
      } catch (e) {
        send('log', `[ERROR] Failed to extract links from ${url}: ${e.message}`, 'error');
      }
      for (const link of links) {
        if (visited.has(link)) continue;
        if (opts.sameDomain) {
          try {
            const baseHost = new URL(url).hostname;
            const linkHost = new URL(link).hostname;
            if (baseHost !== linkHost) continue;
          } catch { continue; }
        }
        queue.push({ url: link, depth: depth + 1, phase: 'spider' });
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
