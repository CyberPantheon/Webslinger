// ai_spider.js
// AI-driven Autonomous XSS Spider for Charlotte (AI agent loop)

const fs = require('fs');
const path = require('path');
const { URL } = "require('url')";
const puppeteer = require('puppeteer');
let JSDOM;
try { JSDOM = require('jsdom').JSDOM; } catch { JSDOM = null; }
const { fork } = require('child_process');

let stopRequested = false;

// --- Utility: Send log to parent process ---
function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}
function log(msg, type = 'info') { send('log', msg, type); }
function reportFinding(finding) { send('finding', finding); }
function reportToUser(msg) { send('ai_report', msg); }
function reportStart(details) { send('ai_report', `[AI-SPIDER] Starting spider:\n${details}`); }
function reportStop(reason) { send('ai_report', `[AI-SPIDER] Stopping spider: ${reason}`); }

// --- Aggressive XSS payloads ---
const DEFAULT_PAYLOADS = [
  `<script>alert(1)</script>`,
  `"><img src=x onerror=alert(1)>`,
  `'><svg/onload=alert(1)>`,
  `"><svg/onload=alert(1)>`,
  `"><body onload=alert(1)>`,
  `"><iframe srcdoc="<script>alert(1)</script>"></iframe>`,
  `javascript:alert(1)`,
  `data:text/html,<script>alert(1)</script>`,
  `"><input autofocus onfocus=alert(1)>`,
  `"><details open ontoggle=alert(1)>`,
  `"><a href=javascript:alert(1)>click</a>`,
];

// --- AI API Call (calls Charlotte backend via keytest.py) ---
async function aiApiCall(state, scope) {
  return new Promise((resolve) => {
    const py = fork(path.join(__dirname, 'keytest.py'), [JSON.stringify([
      {
        role: "user",
        content:
          `You are Charlotte, the browser's AI core and autonomous XSS spider. ` +
          `You have full control to craft and select any payload, for any context (reflected, stored, DOM, CSP bypass, event handlers, JS, URL, etc). ` +
          `You must stay strictly within the user-defined scope: "${scope}". Do not crawl or test outside this scope. ` +
          `You can choose any action: click a link, submit a form, inject a payload, or stop. ` +
          `You must report every action, decision, and finding to the user in detail. ` +
          `If the user sends a stop command, you must halt immediately. ` +
          `Here is the current crawl state:\n` +
          `URL: ${state.url}\n` +
          `Scope: ${scope}\n` +
          `Findings so far: ${JSON.stringify(state.findings)}\n` +
          `Links: ${JSON.stringify(state.links)}\n` +
          `Forms: ${JSON.stringify(state.forms)}\n` +
          `History: ${JSON.stringify(state.history)}\n` +
          `What should be the next action? Respond as JSON: {"action": "...", ...}. ` +
          `If you want to stop, reply {"action": "stop"}.`
      }
    ])]);
    let result = "";
    py.stdout.on('data', d => result += d.toString());
    py.on('close', () => {
      try {
        const parsed = JSON.parse(result);
        let aiAction = null;
        try { aiAction = JSON.parse(parsed.response); } catch { aiAction = null; }
        resolve(aiAction || { action: "stop" });
      } catch {
        resolve({ action: "stop" });
      }
    });
    py.on('error', () => resolve({ action: "stop" }));
  });
}

// --- Helper: Try all payloads in all forms and query params, report every step ---
async function tryAllXSS(page, url, findings, scope) {
  let reported = false;
  const html = await page.content();
  let forms = [];
  let links = [];
  if (JSDOM) {
    const dom = new JSDOM(html);
    forms = [...dom.window.document.querySelectorAll('form')].map(f => ({
      action: f.action || f.getAttribute('action') || '',
      method: f.method || f.getAttribute('method') || 'GET',
      inputs: [...f.querySelectorAll('input[name],textarea[name]')].map(i => ({ name: i.name, type: i.type }))
    }));
    links = [...dom.window.document.querySelectorAll('a[href]')].map(a => a.href);
  }

  // --- Test all forms ---
  for (let i = 0; i < forms.length; ++i) {
    const form = forms[i];
    for (let payload of DEFAULT_PAYLOADS) {
      let params = {};
      for (let inp of form.inputs) params[inp.name] = payload;
      reportToUser(`[AI-SPIDER] Submitting form #${i} (${form.method}) at ${form.action || url} with payload: ${payload}`);
      try {
        if (form.method.toUpperCase() === "POST") {
          await page.evaluate((idx, p) => {
            const f = document.forms[idx];
            if (!f) return;
            for (let el of f.elements) if (el.name) el.value = p;
            f.submit();
          }, i, payload);
        } else {
          // GET: set values and submit
          await page.evaluate((idx, p) => {
            const f = document.forms[idx];
            if (!f) return;
            for (let el of f.elements) if (el.name) el.value = p;
            f.submit();
          }, i, payload);
        }
        await page.waitForTimeout(1000);
        const newHtml = await page.content();
        if (newHtml.includes(payload)) {
          findings.push({ type: 'Reflected', url, payload, evidence: 'Payload reflected in DOM', form: i });
          reportToUser(`[AI-SPIDER] [XSS] Payload reflected in DOM after form submit: ${payload}`);
          reported = true;
        }
      } catch (e) {
        reportToUser(`[AI-SPIDER] Error submitting form #${i}: ${e.message}`);
      }
    }
  }

  // --- Test all query params ---
  try {
    const urlObj = new URL(url);
    const params = Array.from(urlObj.searchParams.keys());
    for (let param of params) {
      for (let payload of DEFAULT_PAYLOADS) {
        urlObj.searchParams.set(param, payload);
        const testUrl = urlObj.toString();
        reportToUser(`[AI-SPIDER] Testing query param "${param}" at ${testUrl} with payload: ${payload}`);
        try {
          await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
          const newHtml = await page.content();
          if (newHtml.includes(payload)) {
            findings.push({ type: 'Reflected', url: testUrl, payload, param, evidence: 'Payload reflected in DOM' });
            reportToUser(`[AI-SPIDER] [XSS] Payload reflected in DOM for param "${param}": ${payload}`);
            reported = true;
          }
        } catch (e) {
          reportToUser(`[AI-SPIDER] Error testing param "${param}": ${e.message}`);
        }
      }
    }
  } catch (e) {
    reportToUser(`[AI-SPIDER] Error parsing URL for query param testing: ${e.message}`);
  }

  // --- Test DOM injection ---
  for (let payload of DEFAULT_PAYLOADS) {
    reportToUser(`[AI-SPIDER] Injecting payload into DOM: ${payload}`);
    try {
      await page.evaluate(p => {
        let div = document.createElement('div');
        div.innerHTML = p;
        document.body.appendChild(div);
      }, payload);
      const newHtml = await page.content();
      if (newHtml.includes(payload)) {
        findings.push({ type: 'DOM', url, payload, evidence: 'Payload injected into DOM' });
        reportToUser(`[AI-SPIDER] [XSS] Payload injected and reflected in DOM: ${payload}`);
        reported = true;
      }
    } catch (e) {
      reportToUser(`[AI-SPIDER] Error injecting DOM payload: ${e.message}`);
    }
  }

  // --- Test event handler injection ---
  for (let payload of DEFAULT_PAYLOADS) {
    reportToUser(`[AI-SPIDER] Injecting payload as event handler: ${payload}`);
    try {
      await page.evaluate(p => {
        let btn = document.createElement('button');
        btn.setAttribute('onclick', p);
        btn.innerText = "Click me";
        document.body.appendChild(btn);
      }, payload);
      // Optionally click the button
      await page.evaluate(() => {
        const btn = document.querySelector('button[onclick]');
        if (btn) btn.click();
      });
      // No direct way to detect alert, but can check for payload in DOM
      const newHtml = await page.content();
      if (newHtml.includes(payload)) {
        findings.push({ type: 'EventHandler', url, payload, evidence: 'Payload injected as event handler' });
        reportToUser(`[AI-SPIDER] [XSS] Payload injected as event handler: ${payload}`);
        reported = true;
      }
    } catch (e) {
      reportToUser(`[AI-SPIDER] Error injecting event handler payload: ${e.message}`);
    }
  }

  if (!reported) {
    reportToUser(`[AI-SPIDER] No XSS found on ${url} with aggressive payloads.`);
  }
}

// --- Main AI Spider Agent Loop ---
async function aiSpider({ startUrl, maxSteps = 15, scope }) {
  let currentUrl = startUrl;
  let step = 0;
  let findings = [];
  let history = [];
  stopRequested = false;

  // Determine scope: default to domain of startUrl if not provided
  let scopePrefix = scope || (new URL(startUrl).origin);

  reportStart(`Target: ${startUrl}\nScope: ${scopePrefix}\nMax Steps: ${maxSteps}`);

  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  while (step < maxSteps && !stopRequested) {
    if (!currentUrl.startsWith(scopePrefix)) {
      reportToUser(`[AI-SPIDER] URL ${currentUrl} is out of scope (${scopePrefix}). Stopping.`);
      break;
    }
    reportToUser(`[AI-SPIDER] Navigating to: ${currentUrl}`);
    await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });

    // Aggressive XSS testing at every step
    await tryAllXSS(page, currentUrl, findings, scopePrefix);

    // Extract links for next step
    let links = [];
    try {
      const html = await page.content();
      if (JSDOM) {
        const dom = new JSDOM(html);
        links = [...dom.window.document.querySelectorAll('a[href]')].map(a => a.href)
          .filter(h => h && h.startsWith(scopePrefix));
      }
    } catch (e) {
      reportToUser(`[AI-SPIDER] Error extracting links: ${e.message}`);
    }

    // Ask AI for next action (with full context)
    const aiInput = {
      url: currentUrl,
      findings,
      links,
      step,
      history
    };
    const aiResponse = await aiApiCall(aiInput, scopePrefix);

    let reportMsg = `[AI-SPIDER] Step ${step + 1}:\n`;
    if (aiResponse && aiResponse.action) {
      reportMsg += `AI decided to perform action: "${aiResponse.action}"`;
      if (aiResponse.url) reportMsg += ` on URL: ${aiResponse.url}`;
      if (aiResponse.form_index !== undefined) reportMsg += ` on form #${aiResponse.form_index}`;
      if (aiResponse.payload) reportMsg += ` with payload: ${aiResponse.payload}`;
      reportMsg += '.\n';
    } else {
      reportMsg += `AI did not specify a valid action. Stopping.`;
    }
    reportToUser(reportMsg);

    await new Promise(res => setTimeout(res, 800));

    log(`[AI] Step ${step} - AI response: ${JSON.stringify(aiResponse)}`);
    history.push({ input: aiInput, ai: aiResponse });

    if (!aiResponse || aiResponse.action === "stop" || stopRequested) {
      reportStop(`AI decided to stop at step ${step + 1}.`);
      break;
    }

    if (aiResponse.action === "click_link" && aiResponse.url) {
      if (!aiResponse.url.startsWith(scopePrefix)) {
        reportToUser(`[AI-SPIDER] AI tried to click out-of-scope link: ${aiResponse.url}. Stopping.`);
        break;
      }
      currentUrl = aiResponse.url;
    } else if (aiResponse.action === "submit_form" && aiResponse.form_index !== undefined && aiResponse.payload) {
      // Already handled in tryAllXSS, so just move to next step
      reportToUser(`[AI-SPIDER] Skipping redundant form submit (already tested).`);
    } else if (aiResponse.action === "inject_payload" && aiResponse.payload) {
      // Already handled in tryAllXSS, so just move to next step
      reportToUser(`[AI-SPIDER] Skipping redundant DOM injection (already tested).`);
    } else {
      reportToUser(`[AI-SPIDER] Unknown or unsupported action "${aiResponse && aiResponse.action}". Stopping.`);
      break;
    }
    step++;
  }
  await browser.close();
  log(`[AI-SPIDER] Finished after ${step} steps. Findings: ${findings.length}`);
  reportToUser(`[AI-SPIDER] Finished after ${step} steps. Total findings: ${findings.length}`);
  return findings;
}

// --- IPC/CLI trigger for Charlotte ---
if (require.main === module) {
  // CLI mode: node ai_spider.js <url> [scope]
  const url = process.argv[2];
  const scope = process.argv[3];
  if (!url) {
    console.error("Usage: node ai_spider.js <url> [scope]");
    process.exit(1);
  }
  aiSpider({ startUrl: url, scope }).then(() => process.exit(0));
}

// Listen for IPC from parent (Charlotte/AI)
process.on('message', async (msg) => {
  if (!msg || !msg.type) return;
  if (msg.type === 'ai_spider_start') {
    const opts = msg.data || {};
    stopRequested = false;
    await aiSpider({
      startUrl: opts.url,
      maxSteps: opts.maxSteps || 25,
      scope: opts.scope
    });
    process.send && process.send({ type: 'ai_spider_done' });
  } else if (msg.type === 'ai_spider_stop') {
    stopRequested = true;
    reportStop('User requested stop.');
  }
});

// Expose for preload or contextBridge if needed
module.exports = {
  start: (opts) => process.send({ type: 'ai_spider_start', data: opts }),
  stop: () => process.send({ type: 'ai_spider_stop' }),
};
