/**
 * paramhunter.js
 *
 * Main script for the ParamHunter tool (Renderer Process).
 * Handles UI, initiates URL fetching/crawling via IPC, analyzes parameters,
 * tags potential vulnerabilities, and displays results.
 */

// Basic check if running in Electron renderer process
const isElectron = typeof require === 'function';
const ipcRendererAvailable = isElectron && typeof require('electron').ipcRenderer?.invoke === 'function';

const ipcRenderer = ipcRendererAvailable ? require('electron').ipcRenderer : {
    send: (channel, ...args) => console.warn(`IPC stub: send('${channel}', ${args.join(', ')}) called. Not in Electron.`),
    invoke: async (channel, ...args) => {
        console.warn(`IPC stub: invoke('${channel}', ${args.join(', ')}) called. Not in Electron or IPC unavailable.`);
        // Simulate some basic responses for testing outside Electron if needed
        if (channel === 'paramhunter:fetch-url') return { body: '<html><body><a href="/?id=1">Link</a><script>var x="?test=2";</script></body></html>', finalUrl: args[0]?.url || 'http://stub.com', statusCode: 200 };
        if (channel === 'paramhunter:save-results') return null; // Simulate cancellation
        throw new Error(`IPC not available for channel: ${channel}. Run within Electron and ensure main process handlers are set up.`);
    }
};

// --- DOM Elements ---
let targetUrlsTextarea, crawlHtmlCheckbox, crawlJsCheckbox, useWaybackCheckbox;
let checkFormsCheckbox, includeHeadersCookiesCheckbox;
let threadsInput, timeoutInput, crawlDepthInput;
let startHuntBtn, stopHuntBtn, clearBtn, exportBtn;
let loadingOverlay, loadingText, progressBar, progressText;
let resultsBody, logContent;
let urlsFoundEl, urlsProcessedEl, paramsFoundEl, vulnsTaggedEl, elapsedTimeEl;
let filterResultsInput, filterVulnTypeSelect;
let headersTextarea, cookiesTextarea;

// --- State Variables ---
let isHunting = false;
let abortController = null; // Simple flag-based abort controller
let discoveredParams = []; // { id, url, paramName, paramValueExample, source ('url', 'form', 'js', 'wayback'), tags: ['XSS', 'SQLi'], timestamp }
let resultCounter = 0;
let startTime = 0;
let elapsedTimeInterval = null;
let urlsToProcess = new Set();
let processedUrls = new Set();
let urlsFoundCount = 0;
let urlsProcessedCount = 0;
let paramsFoundCount = 0;
let vulnsTaggedCount = 0;
let activeTasks = 0;

// --- Constants ---
const severityLevels = { // Reusing from injection-tester for logging consistency
    INFO: 'Info',
    WARNING: 'Warning',
    ERROR: 'Error',
    SUCCESS: 'Success',
    DEBUG: 'Debug' // For verbose logging
};

// --- Enhanced Parameter Patterns ---
const PARAM_PATTERNS = {
    // XSS
    '(q|query|search|s|keyword|searchtext|term|k|searchquery|search_query|search-query|keywords)': ['XSS'],
    '(callback|cb|jsonp|jscallback|jsoncallback)': ['XSS', 'JSONP'],
    '(name|username|user|userid|uid|nickname|login|log|usr)': ['XSS', 'IDOR'],
    '(message|msg|text|comment|subject|body|content|feedback|review)': ['XSS'],
    '(redirect|url|return|next|goto|redirect_to|redirect_uri|return_to|dest|destination|redir|returnUrl|returnURL|forward|referrer|referer)': ['XSS', 'Open Redirect', 'SSRF'], // SSRF possible if URL fetched server-side
    '(email|mail|em)': ['XSS'],
    '(bio|profile|about|description|desc)': ['XSS'],
    '(file|filename|path|pathname|document|img|image|resource|page|include|load|view|show|display|template|style)': ['XSS', 'LFI', 'SSRF'], // LFI/SSRF possible
    '(lang|language|locale)': ['XSS', 'LFI'],

    // SQLi
    '(id|item|pid|product_id|prod_id|p_id|cat|category|cat_id|category_id|article|aid|article_id|user_id|uid|userid|account|number|order|no|jobid)': ['SQLi', 'IDOR'],
    '(select|from|where|union|order|by|group|insert|update|delete)': ['SQLi'], // Keywords directly in param names (less common but possible)
    '(sort|sort_by|order_by|orderby)': ['SQLi'],
    '(filter|criteria|field)': ['SQLi'],

    // SSRF / LFI
    '(url|uri|u|site|host|domain|proxy|fetch|remote|feed|rss|report|external|api_url|service_url)': ['SSRF', 'XSS'],
    '(path|file|dir|directory|folder|include|require|import|template|document|resource|show|view)': ['LFI', 'SSRF'], // SSRF if path is URL-like
    '(config|cfg|conf|ini|env|setting|properties)': ['LFI'],

    // Open Redirect
    '(redirect|url|return|next|goto|redirect_to|redirect_uri|return_to|dest|destination|redir|returnUrl|returnURL|forward)': ['Open Redirect', 'XSS'],

    // IDOR
     '(id|uid|user_id|account_id|profile_id|order_id|message_id|doc_id|item_id|customer_id|cid|pid|edit_id|delete_id|object_id)': ['IDOR', 'SQLi'],

    // Other potential issues (less specific)
    '(debug|test|enable|disable|admin|root|mode)': ['Other'],
    '(token|csrf|nonce|key|secret|auth|pass|pwd|password|api_key|session|sid|sessid)': ['Other'], // Sensitive names

    // Add more patterns for fuzzier matching and more vuln types
    '(xss|cross.?site.?scripting|script|onerror|onload|onmouseover|alert|prompt|confirm)': ['XSS'],
    '(sql|sqli|injection|union|select|from|where|drop|update|delete|insert|into|table|column|database)': ['SQLi'],
    '(ssrf|server.?side.?request|fetch|proxy|internal|localhost|127\\.0\\.0\\.1|url|uri|endpoint|dest|destination)': ['SSRF'],
    '(lfi|rfi|file|path|dir|directory|folder|include|require|import|template|document|resource|show|view|download)': ['LFI', 'RFI'],
    '(open.?redirect|redirect|redir|next|goto|forward|return|url|uri|dest|destination)': ['Open Redirect'],
    '(idor|insecure.?direct.?object|id|uid|user|userid|account|profile|order|message|doc|item|customer|cid|pid|edit|delete|object)': ['IDOR'],
    '(csrf|xsrf|token|nonce|key|secret|auth|pass|pwd|password|api_key|session|sid|sessid)': ['CSRF', 'Sensitive'],
    '(debug|test|enable|disable|admin|root|mode|dev|development|beta|stage|staging)': ['Other'],
    // Fuzzy catch-all for common param names
    '([a-z0-9_]{2,30})': ['Other']
};
const PARAM_PATTERNS_REGEX = Object.keys(PARAM_PATTERNS).map(pattern => ({
    regex: new RegExp(`^(${pattern})$`, 'i'),
    tags: PARAM_PATTERNS[pattern]
}));


// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
    initializeElements();
    setupEventListeners();
    addLog("ParamHunter initialized.", severityLevels.INFO);
    updateUIState();
    initializeTabs(); // Reusing from injection-tester
});

function initializeElements() {
    targetUrlsTextarea = document.getElementById("target-urls");
    crawlHtmlCheckbox = document.getElementById("crawl-html");
    crawlJsCheckbox = document.getElementById("crawl-js");
    useWaybackCheckbox = document.getElementById("use-wayback");
    checkFormsCheckbox = document.getElementById("check-forms");
    includeHeadersCookiesCheckbox = document.getElementById("include-headers-cookies");
    threadsInput = document.getElementById("threads");
    timeoutInput = document.getElementById("timeout");
    crawlDepthInput = document.getElementById("crawl-depth");
    startHuntBtn = document.getElementById("start-hunt-btn");
    stopHuntBtn = document.getElementById("stop-hunt-btn");
    clearBtn = document.getElementById("clear-btn");
    exportBtn = document.getElementById("export-btn");
    loadingOverlay = document.getElementById("loading-overlay");
    loadingText = document.getElementById("loading-text");
    progressBar = document.getElementById("progress-bar");
    progressText = document.getElementById("progress-text");
    resultsBody = document.getElementById("results-body");
    logContent = document.getElementById("log-content");
    urlsFoundEl = document.getElementById("urls-found");
    urlsProcessedEl = document.getElementById("urls-processed");
    paramsFoundEl = document.getElementById("params-found");
    vulnsTaggedEl = document.getElementById("vulns-tagged");
    elapsedTimeEl = document.getElementById("elapsed-time");
    filterResultsInput = document.getElementById("filter-results");
    filterVulnTypeSelect = document.getElementById("filter-vuln-type");
    headersTextarea = document.getElementById("headers-input");
    cookiesTextarea = document.getElementById("cookies-input");
}

function setupEventListeners() {
    if (ipcRendererAvailable) {
        document.getElementById("minimize-btn")?.addEventListener("click", () => ipcRenderer.send("paramhunter:minimize-window"));
        document.getElementById("close-btn")?.addEventListener("click", () => ipcRenderer.send("paramhunter:close-window"));
    }

    startHuntBtn.addEventListener("click", startHunt);
    stopHuntBtn.addEventListener("click", stopHunt);
    clearBtn.addEventListener("click", clearAll);
    exportBtn.addEventListener("click", exportResults);
    targetUrlsTextarea.addEventListener("input", updateUIState); // Add this line

    filterResultsInput.addEventListener("input", renderResults);
    filterVulnTypeSelect.addEventListener("change", renderResults);

    // Tab navigation (reusing from injection-tester)
    const tabNav = document.querySelector('.tab-navigation');
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabNav?.addEventListener('click', (event) => {
        const button = event.target.closest('.tab-btn');
        if (!button || button.classList.contains('active')) return;

        tabNav.querySelector('.tab-btn.active')?.classList.remove('active');
        button.classList.add('active');

        const targetTabId = button.dataset.tab;
        tabPanes.forEach(pane => {
            pane.classList.toggle('active', pane.id === targetTabId);
        });
    });
}

function initializeTabs() { // Reusing from injection-tester
     const activeTabButton = document.querySelector('.tab-navigation .tab-btn.active');
     const activeTabId = activeTabButton ? activeTabButton.dataset.tab : 'results-tab'; // Default to results
     document.querySelectorAll('.tab-pane').forEach(pane => {
         pane.classList.toggle('active', pane.id === activeTabId);
     });
}

// --- Core Logic ---

function getUrlsFromInput() {
    const lines = targetUrlsTextarea.value.split('\n');
    return lines
        .map(line => line.trim())
        .filter(line => line.length > 0 && isValidHttpUrl(line)) // Basic validation
        .map(url => { try { return new URL(url).toString(); } catch { return null; } }) // Normalize and ensure validity
        .filter(url => url !== null);
}

async function startHunt() {
    if (isHunting) return;
    if (!ipcRendererAvailable) {
        addLog("Cannot start hunt: Electron IPC is not available.", severityLevels.ERROR);
        alert("Error: IPC unavailable."); return;
    }

    const initialUrls = getUrlsFromInput();
    if (initialUrls.length === 0) {
        alert("Please enter at least one valid HTTP/HTTPS URL.");
        return;
    }

    // --- Reset State ---
    isHunting = true;
    abortController = { aborted: false }; // Reset abort flag
    discoveredParams = [];
    resultCounter = 0;
    urlsToProcess = new Set(initialUrls);
    processedUrls = new Set();
    urlsFoundCount = initialUrls.length;
    urlsProcessedCount = 0;
    paramsFoundCount = 0;
    vulnsTaggedCount = 0;
    activeTasks = 0;
    renderResults(); // Clear results table
    clearStats(); // Clear stats display
    updateUIState();
    startTime = Date.now();
    elapsedTimeInterval = setInterval(updateElapsedTime, 1000);
    updateProgress(0);

    const maxDepth = parseInt(crawlDepthInput.value, 10) || 0;
    const maxConcurrency = parseInt(threadsInput.value, 10) || 5;

    showLoading(`Starting hunt on ${initialUrls.length} initial URL(s)...`);
    addLog(`Starting ParamHunter. Initial URLs: ${initialUrls.length}, Max Depth: ${maxDepth}, Concurrency: ${maxConcurrency}`, severityLevels.INFO);

    // --- Concurrency Control & Task Management ---
    const queue = Array.from(urlsToProcess).map(url => ({ url, depth: 0 })); // Initial queue with depth 0
    urlsToProcess.clear(); // Clear the set as items are moved to the queue

    // --- Worker Loop ---
    // Pass maxDepth to processUrl
    const processUrl = async (urlToProcess, currentDepth) => {
        if (abortController.aborted || processedUrls.has(urlToProcess) || currentDepth > maxDepth) {
            return [];
        }
        activeTasks++;
        processedUrls.add(urlToProcess);
        urlsProcessedCount++;
        updateStats();
        updateProgress(Math.round((urlsProcessedCount / Math.max(urlsFoundCount, urlsProcessedCount)) * 100));
        let newUrlsFound = [];
        try {
            addLog(`Workspaceing: ${urlToProcess} (Depth: ${currentDepth})`, severityLevels.DEBUG);
            const response = await fetchUrlIPC(urlToProcess);
            if (response && response.body && response.statusCode < 400) {
                const finalUrl = response.finalUrl || urlToProcess;
                addLog(`Processing: ${finalUrl}`, severityLevels.DEBUG);
                extractParamsFromUrl(finalUrl, 'url');
                if (response.body.toLowerCase().includes('<html')) {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(response.body, 'text/html');
                    extractParamsFromHtml(doc, finalUrl, currentDepth, maxDepth, newUrlsFound);
                }
                // JS file crawling
                if (urlToProcess.match(/\.js(\?.*)?$/i) || (response.body && response.body.match(/function|var|let|const|=>/))) {
                    extractParamsFromJs(response.body, urlToProcess, 'js-file');
                    // Extract URLs from JS
                    const urlRegex = /https?:\/\/[^\s"'`<>]+/g;
                    let match;
                    while ((match = urlRegex.exec(response.body)) !== null) {
                        const foundUrl = match[0];
                        if (isValidHttpUrl(foundUrl) && !processedUrls.has(foundUrl)) {
                            newUrlsFound.push({ url: foundUrl, depth: currentDepth + 1 });
                        }
                    }
                }
                // TODO: Wayback/Archive crawling stub
                if (useWaybackCheckbox.checked) {
                    // Placeholder for future: fetch URLs from archive.org, etc.
                }
            } else {
                addLog(`Skipping processing, bad response (${response?.statusCode}) for: ${urlToProcess}`, severityLevels.WARNING);
            }
        } catch (error) {
            if (!abortController.aborted) {
                addLog(`Error processing URL ${urlToProcess}: ${error.message}`, severityLevels.ERROR);
            }
        } finally {
            activeTasks = Math.max(0, activeTasks - 1);
            updateStats();
        }
        return newUrlsFound;
    };

    const runWorker = async () => {
        while (queue.length > 0 || activeTasks > 0) {
            if (abortController.aborted) break;

            if (queue.length > 0 && activeTasks < maxConcurrency) {
                 const { url, depth } = queue.shift(); // Get next URL from queue
                 if (!processedUrls.has(url)) {
                     processUrl(url, depth).then(newUrls => {
                         newUrls.forEach(newItem => {
                             if (!processedUrls.has(newItem.url) && !queue.some(q => q.url === newItem.url)) {
                                 queue.push(newItem);
                                 urlsFoundCount++;
                                 updateStats();
                             }
                         });
                     }).catch(err => { // Catch errors from processUrl promise
                         if (!abortController.aborted) {
                             addLog(`Worker error processing ${url}: ${err.message}`, severityLevels.ERROR);
                         }
                     });
                 }
            } else {
                // Wait if queue is empty but tasks are running, or if concurrency limit reached
                await sleep(100);
            }
        }
    };

    // Start workers
    const workers = Array(maxConcurrency).fill(null).map(() => runWorker());

    try {
        await Promise.all(workers); // Wait for all workers to finish
    } catch (error) {
         if (!abortController.aborted) {
            console.error("Unexpected error during hunt:", error);
            addLog(`Unexpected hunting error: ${error.message}`, severityLevels.ERROR);
         }
    } finally {
        stopHunt(); // Clean up state, timers etc.
        if (abortController.aborted) {
            addLog(`Hunt stopped by user. Processed ${urlsProcessedCount} URLs. Found ${paramsFoundCount} parameters.`, severityLevels.INFO);
        } else {
             addLog(`Hunt finished. Processed ${urlsProcessedCount} URLs. Found ${paramsFoundCount} parameters. Tagged ${vulnsTaggedCount} potential vulnerabilities.`, severityLevels.SUCCESS);
        }
        updateUIState();
        if (!abortController.aborted && discoveredParams.length > 0) {
            exportBtn.disabled = false; // Enable export if results exist and not aborted
        }
    }
}

function stopHunt() {
    if (abortController && !abortController.aborted) {
        addLog("Stopping hunt...", severityLevels.INFO);
        abortController.aborted = true;
    }
    if (elapsedTimeInterval) {
        clearInterval(elapsedTimeInterval);
        elapsedTimeInterval = null;
    }
    isHunting = false;
    activeTasks = 0;
    hideLoading();
    updateUIState();
    updateStats(); // Update final stats display
}

function clearAll() {
    if (isHunting) {
        alert("Cannot clear while hunting is in progress. Stop the hunt first.");
        return;
    }
    discoveredParams = [];
    resultCounter = 0;
    urlsToProcess = new Set();
    processedUrls = new Set();
    logContent.innerHTML = '';
    targetUrlsTextarea.value = '';
    renderResults();
    clearStats();
    updateUIState();
    addLog("Cleared results, logs, and target URLs.", severityLevels.INFO);
}

function clearStats() {
    urlsFoundCount = 0;
    urlsProcessedCount = 0;
    paramsFoundCount = 0;
    vulnsTaggedCount = 0;
    startTime = 0;
    activeTasks = 0;
    if (elapsedTimeInterval) {
        clearInterval(elapsedTimeInterval);
        elapsedTimeInterval = null;
    }
    elapsedTimeEl.textContent = "00:00";
    updateStats();
    updateProgress(0);
}

async function exportResults() {
    if (discoveredParams.length === 0) { alert("No results to export."); return; }
    if (!ipcRendererAvailable) { alert("Export requires Electron IPC."); return; }

    const defaultFileName = `paramhunter_results_${new Date().toISOString().split('T')[0]}.json`;
    addLog("Attempting to export results...", severityLevels.INFO);

    try {
        const filePath = await ipcRenderer.invoke('paramhunter:save-results', { // Use specific channel
            defaultPath: defaultFileName,
            results: discoveredParams,
            format: 'json' // Or allow choosing format later
        });

        if (filePath && typeof filePath === 'string') {
            addLog(`Results successfully exported to: ${filePath}`, severityLevels.SUCCESS);
            alert(`Results exported to:\n${filePath}`);
        } else {
            addLog("Result export cancelled or failed.", severityLevels.INFO);
        }
    } catch (err) {
        console.error("Export Error:", err);
        addLog(`Failed to export results: ${err.message}`, severityLevels.ERROR);
        alert(`Failed to export results: ${err.message}`);
    }
}

// --- Parameter Extraction and Tagging ---

function extractParamsFromUrl(url, source) {
    try {
        const urlObj = new URL(url);
        urlObj.searchParams.forEach((value, name) => {
            addParameter(url, name, source, value);
        });
        // Also check hash fragment for params
        if (urlObj.hash && urlObj.hash.includes('=')) {
            urlObj.hash.replace(/^#/, '').split('&').forEach(pair => {
                const [name, value] = pair.split('=');
                if (name) addParameter(url, name, source + '-hash', value);
            });
        }
    } catch (e) {
        addLog(`Failed to parse URL for param extraction: ${url}`, severityLevels.WARNING);
    }
}

// --- Enhanced JS Parameter Extraction ---
function extractParamsFromJs(jsContent, baseUrl, source) {
    // Improved regexes for JS param detection
    const patterns = [
        /["'`]([a-zA-Z0-9_\-]{2,40})["'`]\s*:/g, // JSON keys
        /([a-zA-Z0-9_\-]{2,40})\s*=/g, // Variable assignments
        /["'`][?&]([a-zA-Z0-9_\-]{2,40})=/g, // Query params in strings
        /params\s*\[\s*['"`]([^'"`]+)['"`]\s*\]/g,
        /\.set\(['"`]([^'"`]+)['"`]/g,
        /getParameter\(['"`]([^'"`]+)['"`]/g,
        /location\.search.*?([a-zA-Z0-9_\-]{2,40})/g,
        /document\.cookie.*?([a-zA-Z0-9_\-]{2,40})/g
    ];
    let match;
    patterns.forEach(regex => {
        while ((match = regex.exec(jsContent)) !== null) {
            const paramName = match[1];
            if (paramName && paramName.length > 1 && paramName.length < 50 && !/^\d+$/.test(paramName)) {
                addParameter(baseUrl, paramName, source + '-js');
            }
        }
    });
    // Extract URLs from JS strings
    const urlRegex = /["'`](https?:\/\/[^\s"'`<>]+)["'`]/g;
    while ((match = urlRegex.exec(jsContent)) !== null) {
        const foundUrl = match[1];
        if (isValidHttpUrl(foundUrl)) {
            extractParamsFromUrl(foundUrl, source + '-js-url');
        }
    }
}

function extractParamsFromHtml(doc, finalUrl, currentDepth, maxDepth, newUrlsFound) {
    // Links
    doc.querySelectorAll('a[href], area[href], link[href]').forEach(link => {
        const href = link.getAttribute('href');
        if (href) {
            try {
                const absoluteUrl = new URL(href, finalUrl).toString();
                extractParamsFromUrl(absoluteUrl, 'html-link');
                if (crawlHtmlCheckbox.checked && isSameOrigin(finalUrl, absoluteUrl) && currentDepth < maxDepth && !processedUrls.has(absoluteUrl)) {
                    newUrlsFound.push({ url: absoluteUrl, depth: currentDepth + 1 });
                }
            } catch {}
        }
    });
    // Forms (GET/POST, including hidden fields)
    if (checkFormsCheckbox.checked) {
        doc.querySelectorAll('form').forEach(form => {
            const method = (form.getAttribute('method') || 'GET').toUpperCase();
            let actionUrl = form.getAttribute('action');
            try {
                actionUrl = actionUrl ? new URL(actionUrl, finalUrl).toString() : finalUrl;
                form.querySelectorAll('input[name], textarea[name], select[name]').forEach(input => {
                    const paramName = input.getAttribute('name');
                    if (paramName) {
                        addParameter(actionUrl, paramName, `form-${method.toLowerCase()}`);
                    }
                });
            } catch {}
        });
    }
    // Data attributes
    doc.querySelectorAll('[data-*]').forEach(el => {
        Array.from(el.attributes).forEach(attr => {
            if (attr.name.startsWith('data-')) {
                addParameter(finalUrl, attr.name, 'html-data-attr');
            }
        });
    });
    // Inline event handlers (onerror, onclick, etc)
    doc.querySelectorAll('*').forEach(el => {
        Array.from(el.attributes).forEach(attr => {
            if (/^on[a-z]+$/i.test(attr.name)) {
                extractParamsFromJs(attr.value, finalUrl, 'html-inline-event');
            }
        });
    });
    // Script tags
    doc.querySelectorAll('script').forEach(script => {
        const scriptContent = script.textContent || '';
        extractParamsFromJs(scriptContent, finalUrl, 'html-inline-js');
        const src = script.getAttribute('src');
        if (crawlJsCheckbox.checked && src) {
            try {
                const scriptUrl = new URL(src, finalUrl).toString();
                extractParamsFromUrl(scriptUrl, 'html-script-src');
                if (isSameOrigin(finalUrl, scriptUrl) && !processedUrls.has(scriptUrl)) {
                    newUrlsFound.push({ url: scriptUrl, depth: currentDepth + 1, isJs: true });
                }
            } catch {}
        }
    });
    // Extract URLs from src/href attributes of all elements
    doc.querySelectorAll('[src], [href]').forEach(el => {
        ['src', 'href'].forEach(attr => {
            const val = el.getAttribute(attr);
            if (val) {
                try {
                    const absUrl = new URL(val, finalUrl).toString();
                    extractParamsFromUrl(absUrl, 'html-attr');
                    if (crawlHtmlCheckbox.checked && isSameOrigin(finalUrl, absUrl) && currentDepth < maxDepth && !processedUrls.has(absUrl)) {
                        newUrlsFound.push({ url: absUrl, depth: currentDepth + 1 });
                    }
                } catch {}
            }
        });
    });
}

// --- Enhanced getPotentialVulnTags ---
function getPotentialVulnTags(paramName) {
    const foundTags = new Set();
    const lowerParamName = paramName.toLowerCase();
    PARAM_PATTERNS_REGEX.forEach(pattern => {
        if (pattern.regex.test(lowerParamName)) {
            pattern.tags.forEach(tag => foundTags.add(tag));
        }
    });
    // Fuzzy/heuristic checks
    if (foundTags.size === 0) {
        if (lowerParamName.match(/(url|redirect|next|goto|return|dest|forward)/)) foundTags.add('Open Redirect');
        if (lowerParamName.match(/(file|path|page|dir|folder|include|require|import)/)) foundTags.add('LFI');
        if (lowerParamName.match(/(id|user|account|profile|order|doc|item|customer|cid|pid|edit|delete|object)/)) foundTags.add('IDOR');
        if (lowerParamName.match(/(token|csrf|xsrf|nonce|key|secret|auth|pass|pwd|password|api_key|session|sid|sessid)/)) foundTags.add('Sensitive');
        if (lowerParamName.match(/(sql|union|select|from|where|drop|update|delete|insert|into|table|column|database)/)) foundTags.add('SQLi');
        if (lowerParamName.match(/(xss|script|onerror|onload|onmouseover|alert|prompt|confirm)/)) foundTags.add('XSS');
        if (lowerParamName.match(/(ssrf|proxy|internal|localhost|127\.0\.0\.1|endpoint)/)) foundTags.add('SSRF');
    }
    return Array.from(foundTags);
}

// --- Enhanced addParameter (deduplication) ---
function addParameter(url, paramName, source, valueExample = '') {
    if (!paramName) return;
    // Deduplicate by url, paramName, and source
    const existingIndex = discoveredParams.findIndex(
        p => p.url === url && p.paramName === paramName && p.source === source
    );
    if (existingIndex !== -1) return;
    const tags = getPotentialVulnTags(paramName);
    paramsFoundCount++;
    if (tags.length > 0) vulnsTaggedCount++;
    updateStats();
    addResult({
        url: url,
        paramName: paramName,
        paramValueExample: valueExample,
        source: source,
        tags: tags,
    });
}

// --- IPC Communication ---

async function fetchUrlIPC(url) {
    if (!ipcRendererAvailable) {
         throw new Error("IPC not available for fetching URL.");
    }
    try {
        // Add slight random delay to avoid overwhelming server/detection
        await sleep(Math.random() * 150 + 50);

        const response = await ipcRenderer.invoke('paramhunter:fetch-url', { // Use specific channel
             url: url,
             followRedirects: true, // Usually follow redirects for discovery
             timeout: parseInt(timeoutInput.value, 10) || 10000,
             headers: parseHeadersInput(),
             cookies: parseCookiesInput()
        });
        return response; // Should be { body, finalUrl, statusCode } or throw error
    } catch (error) {
        // Log IPC errors specifically
        addLog(`IPC Error fetching ${url}: ${error.message}`, severityLevels.ERROR);
        // Rethrow or return null/error object for the caller (processUrl) to handle
        // Returning null might be simpler for processUrl to handle gracefully
        return null;
         // throw error; // Or rethrow if processUrl should explicitly catch it
    }
}


// --- UI Update Functions ---

function updateUIState() {
    const hasUrls = targetUrlsTextarea.value.trim() !== '';

    startHuntBtn.disabled = !hasUrls || isHunting;
    stopHuntBtn.disabled = !isHunting;
    clearBtn.disabled = isHunting && (discoveredParams.length === 0 && logContent.children.length <= 1);
    exportBtn.disabled = discoveredParams.length === 0 || isHunting;

    targetUrlsTextarea.disabled = isHunting;
    threadsInput.disabled = isHunting;
    timeoutInput.disabled = isHunting;
    crawlDepthInput.disabled = isHunting;
    crawlHtmlCheckbox.disabled = isHunting;
    crawlJsCheckbox.disabled = isHunting;
    useWaybackCheckbox.disabled = isHunting; // Keep disabled if not implemented
    checkFormsCheckbox.disabled = isHunting;
    includeHeadersCookiesCheckbox.disabled = isHunting; // Keep disabled if not implemented
    headersTextarea.disabled = isHunting;
    cookiesTextarea.disabled = isHunting;
    filterResultsInput.disabled = isHunting;
    filterVulnTypeSelect.disabled = isHunting;
}

function showLoading(text = "Loading...") {
    if (!loadingOverlay || !loadingText) return;
    loadingText.textContent = text;
    loadingOverlay.style.display = "flex";
}

function hideLoading() {
     if (!loadingOverlay) return;
    loadingOverlay.style.display = "none";
}

function updateProgress(percentage) {
     if (!progressBar || !progressText) return;
    const clampedPercentage = Math.max(0, Math.min(100, percentage));
    progressBar.style.width = `${clampedPercentage}%`;
    progressText.textContent = `${Math.round(clampedPercentage)}%`;
}

function updateStats() {
    if (!urlsFoundEl) return; // Check if elements exist
    urlsFoundEl.textContent = urlsFoundCount;
    urlsProcessedEl.textContent = urlsProcessedCount;
    paramsFoundEl.textContent = paramsFoundCount;
    vulnsTaggedEl.textContent = vulnsTaggedCount;
}

function updateElapsedTime() {
    if (!startTime || !elapsedTimeEl) return;
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(elapsed / 3600);
    const minutes = Math.floor((elapsed % 3600) / 60);
    const seconds = elapsed % 60;
    elapsedTimeEl.textContent = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function addLog(message, level = severityLevels.INFO) {
    if (!logContent) return;
    // Optionally filter logs based on a level setting
    // if (level === severityLevels.DEBUG && !debugModeEnabled) return;

    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const logEntry = document.createElement("div");
    logEntry.classList.add("log-entry", `severity-${level.toLowerCase()}`);

    logEntry.innerHTML = `
        <span class="log-timestamp">${timestamp}</span>
        <span class="log-severity">${level}</span>
        <span class="log-message">${escapeHtml(message)}</span>
    `;

    const shouldScroll = logContent.scrollTop + logContent.clientHeight >= logContent.scrollHeight - 20; // Check if near bottom

    logContent.appendChild(logEntry);

    if (shouldScroll) {
        logContent.scrollTop = logContent.scrollHeight; // Auto-scroll only if user is near the bottom
    }
}

function addResult(result) {
    result.id = ++resultCounter;
    result.timestamp = result.timestamp || Date.now();
    discoveredParams.push(result);
    renderResults(); // Update table display
    // updateStats is called within addParameter where vuln counts are updated
}

function renderResults() {
    if (!resultsBody) return;

    const searchTerm = filterResultsInput.value.toLowerCase();
    const selectedVulnType = filterVulnTypeSelect.value;

    const filteredResults = discoveredParams.filter(r => {
        const typeMatch = !selectedVulnType || r.tags.includes(selectedVulnType);
        const searchMatch = !searchTerm ||
                              (r.url && r.url.toLowerCase().includes(searchTerm)) ||
                              (r.paramName && r.paramName.toLowerCase().includes(searchTerm));
        return typeMatch && searchMatch;
    });

    filteredResults.sort((a, b) => b.id - a.id); // Sort newest first

    resultsBody.innerHTML = filteredResults.map(result => {
        const tagsHtml = result.tags.map(tag =>
             `<span class=\"param-tag tag-${tag.toLowerCase().replace(/\\s+/g, '-') }\">${escapeHtml(tag)}</span>`
        ).join(' ');
        // Render the URL as a real anchor tag for copy/open support
        return `
        <tr>
            <td>${result.id}</td>
            <td title="${escapeHtml(result.url)}"><a href="${escapeHtml(result.url)}" class="result-url-link" target="_blank" rel="noopener noreferrer">${escapeHtml(truncateString(result.url, 70))}</a></td>
            <td title="${escapeHtml(result.paramName)}">${escapeHtml(result.paramName)}</td>
            <td>${escapeHtml(result.source)}</td>
            <td><div class="param-tags">${tagsHtml || 'None'}</div></td>
            <td>${new Date(result.timestamp).toLocaleTimeString()}</td>
        </tr>
        `;
    }).join('');

    if (discoveredParams.length > 0 && filteredResults.length === 0) {
         resultsBody.innerHTML = `<tr><td colspan="6" class="placeholder">No parameters match the current filter.</td></tr>`;
    } else if (discoveredParams.length === 0) {
         resultsBody.innerHTML = `<tr><td colspan="6" class="placeholder">No parameters found yet. Start a hunt.</td></tr>`;
    }
    // No custom click handler needed for links
}

// --- Utility Functions (Partially reused from injection-tester) ---

function escapeHtml(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function isValidHttpUrl(string) {
  if (!string) return false;
  try {
      const url = new URL(string);
      return url.protocol === "http:" || url.protocol === "https:";
  } catch (_) {
      return false;
  }
}

function isSameOrigin(url1, url2) {
    try {
        const origin1 = new URL(url1).origin;
        const origin2 = new URL(url2).origin;
        return origin1 === origin2;
    } catch {
        return false; // If URLs are invalid, they aren't the same origin
    }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function truncateString(str, maxLength = 50) {
    if (typeof str !== 'string') return str;
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + "...";
}

function parseHeadersInput() {
    const headers = {};
    if (!headersTextarea) return headers;
    const lines = headersTextarea.value.split('\n');
    lines.forEach(line => {
        const parts = line.match(/^([^:]+):\s*(.*)$/);
        if (parts && parts.length === 3) {
            const key = parts[1].trim();
            const value = parts[2].trim();
            if (key && value) { headers[key] = value; }
        }
    });
    return headers;
}

function parseCookiesInput() {
    if (!cookiesTextarea) return {};
     const cookieString = cookiesTextarea.value.trim().replace(/\n/g, '; ').replace(/\s*;\s*/g, '; ');
     if (cookieString) {
        return { 'Cookie': cookieString };
     }
     return {};
}