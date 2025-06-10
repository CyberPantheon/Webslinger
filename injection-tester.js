/**
 * injection-tester.js
 *
 * Main script for the Injection Tester Electron application (Renderer Process).
 * Handles UI interactions, initiates target analysis via IPC, displays results.
 * Version 3: Added stricter pre-IPC checks.
 *
 * --- IMPORTANT ---
 * This script RELIES ON the Electron MAIN PROCESS to perform network requests.
 * Implement `ipcMain.handle` listeners in your main process file (e.g., main.js)
 * for 'get-app-path', 'fetch-url', 'send-test-request', 'save-file-dialog', 'save-results'.
 */

// Check if running in Electron renderer process, otherwise provide dummy ipcRenderer
const isElectron = typeof require === 'function';
// Basic check if essential IPC methods likely exist (might need refinement)
const ipcRendererAvailable = isElectron && typeof require('electron').ipcRenderer?.invoke === 'function' && typeof require('electron').ipcRenderer?.send === 'function';

const ipcRenderer = ipcRendererAvailable ? require('electron').ipcRenderer : {
    send: (channel) => { console.warn(`IPC stub: send('${channel}') called. Not in Electron.`); },
    invoke: async (channel) => {
        console.warn(`IPC stub: invoke('${channel}') called. Not in Electron or IPC unavailable.`);
        throw new Error(`IPC not available for channel: ${channel}. Run within Electron and ensure preload/main setup is correct.`);
    }
};
const shell = isElectron ? require('electron').shell : { openExternal: (url) => window.open(url) };

// Node.js modules needed in renderer (ensure nodeIntegration/contextIsolation allows, or use preload)
const fs = isElectron ? require("fs") : null;
const path = isElectron ? require("path") : null;

// --- DOM Elements (IDs from HTML) ---
let targetUrlInput, analyzeBtn, wordlistSelect, refreshWordlistsBtn;
let threadsInput, timeoutInput, delayInput;
let followRedirectsCheckbox, autoSaveCheckbox, testAllParamsCheckbox;
let startBtn, stopBtn, clearBtn, exportBtn;
let loadingOverlay, loadingText, progressBar, progressText;
let formsContainer, resultsBody, payloadsContainer, logContent;
let totalRequestsEl, elapsedTimeEl, requestsPerSecondEl, vulnsFoundEl;
let formsTestedEl, paramsTestedEl;
let filterResultsInput, filterTypeSelect, filterSeveritySelect;
let testTypeButtons;
let headersTextarea, cookiesTextarea;

// --- State Variables ---
let isScanning = false;
let isTesting = false;
let currentInjectionType = "xss"; // Default type
let detectedForms = []; // Stores form objects { action, method, inputs: [{name, type}], isPseudoForm }
let selectedInputs = []; // Array of { formIndex: i, inputName: 'name' }
let testResults = []; // { id, type, severity, url, param, payload, details, timestamp }
let payloads = {}; // Loaded payloads { type: [p1, p2, ...] }
let wordlistsDirectory = null;
let abortController = null;
let startTime = 0;
let elapsedTimeInterval = null;
let totalRequests = 0;
let successfulRequests = 0;
let failedRequests = 0;
let vulnerabilitiesFound = 0;
let formsTestedCount = 0;
let paramsTestedCount = 0;
let requestsPerSecond = 0;
let activeRequests = 0;
let resultCounter = 0;

// --- Constants ---
const injectionTypeDescriptions = {
  xss: "Cross-Site Scripting: Injecting client-side scripts.",
  sqli: "SQL Injection: Injecting malicious SQL code.",
  cmdi: "Command Injection: Executing system commands.",
  lfi: "Local File Inclusion: Accessing local files.",
  xxe: "XML External Entity: Exploiting XML parsers.",
  ssrf: "Server-Side Request Forgery: Making the server send requests.",
  ssti: "Server-Side Template Injection: Exploiting template engines."
};

const severityLevels = {
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    INFO: 'Info',
    ERROR: 'Error', // For logging errors
    SUCCESS: 'Success' // For logging success actions
};

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  initializeElements();
  setupEventListeners();

  if (ipcRendererAvailable && path) { // Check if IPC and path seem available
      ipcRenderer.invoke('get-app-path')
          .then(appPath => {
              if (appPath && typeof appPath === 'string') {
                  wordlistsDirectory = path.join(appPath, 'wordlists'); // ADJUST AS NEEDED
                  addLog(`Wordlists directory expected at: ${wordlistsDirectory}`, severityLevels.INFO);
                  loadWordlists(); // Attempt to load lists
              } else {
                  addLog("Could not determine wordlists directory (Invalid path received).", severityLevels.ERROR);
                  disableWordlistUI();
              }
          })
          .catch(err => {
              console.error("Error invoking get-app-path:", err);
              addLog(`Error getting app path from main process: ${err.message}`, severityLevels.ERROR);
              disableWordlistUI();
          });
  } else {
       addLog("Wordlist loading skipped (Electron IPC or Node.js 'path' unavailable).", severityLevels.WARNING);
       disableWordlistUI();
  }

  addLog("Injection Tester initialized.", severityLevels.INFO);
  updateUIState();
  initializeTabs();
});

/** Disable wordlist select and refresh button */
function disableWordlistUI() {
    if (wordlistSelect) {
         wordlistSelect.innerHTML = '<option value="">Unavailable</option>';
         wordlistSelect.disabled = true;
    }
     if (refreshWordlistsBtn) refreshWordlistsBtn.disabled = true;
}

/**
 * Gets references to all necessary DOM elements.
 */
function initializeElements() {
    targetUrlInput = document.getElementById("target-url");
    analyzeBtn = document.getElementById("analyze-btn");
    wordlistSelect = document.getElementById("wordlist-select");
    refreshWordlistsBtn = document.getElementById("refresh-wordlists");
    threadsInput = document.getElementById("threads");
    timeoutInput = document.getElementById("timeout");
    delayInput = document.getElementById("delay");
    followRedirectsCheckbox = document.getElementById("follow-redirects");
    autoSaveCheckbox = document.getElementById("auto-save");
    testAllParamsCheckbox = document.getElementById("test-all-params");
    startBtn = document.getElementById("start-btn");
    stopBtn = document.getElementById("stop-btn");
    clearBtn = document.getElementById("clear-btn");
    exportBtn = document.getElementById("export-btn");
    loadingOverlay = document.getElementById("loading-overlay");
    loadingText = document.getElementById("loading-text");
    progressBar = document.getElementById("progress-bar");
    progressText = document.getElementById("progress-text");
    formsContainer = document.getElementById("forms-container");
    resultsBody = document.getElementById("results-body");
    payloadsContainer = document.getElementById("payloads-container");
    logContent = document.getElementById("log-content");
    totalRequestsEl = document.getElementById("total-requests");
    elapsedTimeEl = document.getElementById("elapsed-time");
    requestsPerSecondEl = document.getElementById("requests-per-second");
    vulnsFoundEl = document.getElementById("vulns-found");
    formsTestedEl = document.getElementById("forms-tested");
    paramsTestedEl = document.getElementById("params-tested");
    filterResultsInput = document.getElementById("filter-results");
    filterTypeSelect = document.getElementById("filter-type");
    filterSeveritySelect = document.getElementById("filter-severity");
    testTypeButtons = document.querySelector(".test-type-buttons");
    headersTextarea = document.getElementById("headers-input");
    cookiesTextarea = document.getElementById("cookies-input");

    // Populate filter dropdowns
    filterTypeSelect.innerHTML = '<option value="">All Types</option>' + Object.keys(injectionTypeDescriptions).map(k => `<option value="${k.toUpperCase()}">${k.toUpperCase()}</option>`).join('');
    filterSeveritySelect.innerHTML = '<option value="">All Severities</option>' + Object.values(severityLevels).filter(s => s !== severityLevels.ERROR && s !== severityLevels.SUCCESS).map(s => `<option value="${s}">${s}</option>`).join('');
}

/**
 * Sets up event listeners for UI elements.
 */
function setupEventListeners() {
    // Window controls (ensure ipcRenderer is available)
    if (ipcRendererAvailable) {
        document.getElementById("minimize-btn")?.addEventListener("click", () => ipcRenderer.send("minimize-window"));
        document.getElementById("close-btn")?.addEventListener("click", () => ipcRenderer.send("close-window"));
    }

    analyzeBtn.addEventListener("click", analyzeTarget);

    testTypeButtons.addEventListener("click", (event) => {
        const button = event.target.closest('button.test-type-btn');
        if (!button || button.disabled || button.classList.contains('active')) return;

        testTypeButtons.querySelector(".active")?.classList.remove("active");
        button.classList.add("active");
        currentInjectionType = button.dataset.type;
        addLog(`Selected test type: ${currentInjectionType.toUpperCase()}`, severityLevels.INFO);
        loadWordlists(); // Attempt to reload wordlists for the new type
        renderPayloads(); // Clear old payloads display
        updateUIState(); // Update button states (e.g., start button)
    });

    refreshWordlistsBtn.addEventListener("click", loadWordlists);
    startBtn.addEventListener("click", startTest);
    stopBtn.addEventListener("click", stopTest);
    clearBtn.addEventListener("click", clearAll);
    exportBtn.addEventListener("click", exportResults); // Changed to use new handler name

    filterResultsInput.addEventListener("input", renderResults);
    filterTypeSelect.addEventListener("change", renderResults);
    filterSeveritySelect.addEventListener("change", renderResults);

    formsContainer.addEventListener('change', (event) => {
        const checkbox = event.target;
        if (checkbox.type !== 'checkbox') return;

        if (checkbox.dataset.inputType === 'param-selector') {
            const formIndex = parseInt(checkbox.dataset.formIndex, 10);
            const inputName = checkbox.dataset.inputName;
            if (checkbox.checked) {
                selectedInputs.push({ formIndex, inputName });
            } else {
                selectedInputs = selectedInputs.filter(inp => !(inp.formIndex === formIndex && inp.inputName === inputName));
                const formCheckbox = formsContainer.querySelector(`#form-select-${formIndex}`);
                if(formCheckbox) formCheckbox.checked = false;
            }
        } else if (checkbox.dataset.inputType === 'form-selector') {
            const formIndex = parseInt(checkbox.dataset.formIndex, 10);
            const isChecked = checkbox.checked;
            formsContainer.querySelectorAll(`input[data-form-index="${formIndex}"][data-input-type="param-selector"]`).forEach(inputCheckbox => {
                 inputCheckbox.checked = isChecked;
                 const inputName = inputCheckbox.dataset.inputName;
                 if (isChecked) {
                     if (!selectedInputs.some(inp => inp.formIndex === formIndex && inp.inputName === inputName)) {
                        selectedInputs.push({ formIndex, inputName });
                     }
                 } else {
                     selectedInputs = selectedInputs.filter(inp => !(inp.formIndex === formIndex && inp.inputName === inputName));
                 }
            });
        }
        updateUIState(); // Update start button availability etc.
    });

    const tabNav = document.querySelector('.tab-navigation');
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabNav.addEventListener('click', (event) => {
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

/** Sets up initial tab visibility */
function initializeTabs() {
     const activeTabButton = document.querySelector('.tab-navigation .tab-btn.active');
     const activeTabId = activeTabButton ? activeTabButton.dataset.tab : 'forms-tab';
     document.querySelectorAll('.tab-pane').forEach(pane => {
         pane.classList.toggle('active', pane.id === activeTabId);
     });
}


// --- Core Logic ---

/** Analyzes target URL for forms and inputs */
async function analyzeTarget() {
    const url = targetUrlInput.value.trim();
    if (!isValidHttpUrl(url)) {
        addLog("Invalid URL provided.", severityLevels.ERROR);
        alert("Please enter a valid HTTP/HTTPS URL.");
        return;
    }
    if (!ipcRendererAvailable) {
         addLog("Cannot analyze: Electron IPC is not available.", severityLevels.ERROR);
         alert("Error: IPC unavailable. Ensure the app is running correctly in Electron.");
         return;
    }

    isScanning = true;
    detectedForms = [];
    selectedInputs = [];
    renderDetectedInputs();
    updateUIState();
    showLoading("Analyzing target URL...");
    addLog(`Analyzing ${url}...`, severityLevels.INFO);

    try {
        addLog(`Requesting URL fetch via IPC: ${url}`, severityLevels.INFO);
        const response = await ipcRenderer.invoke('fetch-url', {
             url: url,
             followRedirects: followRedirectsCheckbox.checked,
             timeout: parseInt(timeoutInput.value, 10) || 15000,
             headers: parseHeadersInput(),
             cookies: parseCookiesInput() // Pass parsed cookies directly
        });

        if (!response || typeof response.body !== 'string' || typeof response.finalUrl !== 'string') {
             throw new Error("Received invalid response from main process fetch handler ('fetch-url').");
        }
        addLog(`Content received successfully from: ${response.finalUrl}`, severityLevels.INFO);

        const htmlContent = response.body;
        const finalUrl = response.finalUrl; // URL after potential redirects

        let doc;
        try {
            const parser = new DOMParser();
            doc = parser.parseFromString(htmlContent, 'text/html');
            if (doc.querySelector('parsererror')) {
                 addLog("HTML parsing error encountered. Results might be incomplete.", severityLevels.WARNING);
            }
            if (!doc || !doc.body) { throw new Error("DOMParser did not return a valid document body."); }
        } catch (parseError) {
            throw new Error(`Failed to parse HTML: ${parseError.message}`);
        }

        const formsFound = [];
        const inputsWithinForms = new Set(); // Store DOM element references

        // 1. Standard forms
        doc.querySelectorAll("form").forEach((formElement, formIndex) => {
            let formAction = finalUrl; // Default to final URL
            const actionAttr = formElement.getAttribute("action");
            if (actionAttr != null && actionAttr.trim() !== '') {
                 try { formAction = new URL(actionAttr, finalUrl).toString(); }
                 catch (e) {
                      addLog(`Invalid form action "${actionAttr}" in form ${formIndex + 1}. Using page URL: ${finalUrl}`, severityLevels.LOW);
                      formAction = finalUrl;
                 }
            }

            const formMethod = (formElement.getAttribute("method") || "GET").toUpperCase();
            const currentFormInputs = [];

            formElement.querySelectorAll("input[name], textarea[name], select[name]").forEach(inputEl => {
                const name = inputEl.getAttribute("name");
                if (name) {
                    const type = inputEl.getAttribute("type") || inputEl.tagName.toLowerCase();
                    currentFormInputs.push({ name: name, type: type });
                    inputsWithinForms.add(inputEl);
                }
            });

            // Only add form if it has inputs
            if (currentFormInputs.length > 0) {
                formsFound.push({
                    action: formAction,
                    method: formMethod,
                    inputs: currentFormInputs, // Ensure 'inputs' array is present
                    isPseudoForm: false
                });
            } else {
                addLog(`Form ${formIndex + 1} (Action: ${formAction}) found but had no named inputs. Skipping.`, severityLevels.INFO);
            }
        });

        // 2. Standalone inputs
        const standaloneInputs = [];
        doc.querySelectorAll("body input[name], body textarea[name], body select[name]").forEach(inputEl => {
            if (!inputsWithinForms.has(inputEl)) { // Check reference equality
                 const name = inputEl.getAttribute("name");
                 if (name) {
                     const type = inputEl.getAttribute("type") || inputEl.tagName.toLowerCase();
                     standaloneInputs.push({ name: name, type: type });
                 }
             }
        });

        if (standaloneInputs.length > 0) {
            formsFound.push({
                action: finalUrl, // Target is the page itself
                method: 'GET',    // Assume GET for standalone params (likely URL params)
                inputs: standaloneInputs, // Ensure 'inputs' array is present
                isPseudoForm: true
            });
        }

        detectedForms = formsFound;

        const formCount = detectedForms.filter(f => !f.isPseudoForm).length;
        const standaloneGroupCount = detectedForms.filter(f => f.isPseudoForm).length; // Should be 0 or 1
        if (detectedForms.length > 0) {
             const totalInputs = detectedForms.reduce((sum, form) => sum + (form.inputs ? form.inputs.length : 0), 0); // Safely sum inputs
             addLog(`Analysis complete. Found ${formCount} <form>(s)${standaloneGroupCount > 0 ? ' and 1 group of standalone inputs' : ''}. Total testable inputs: ${totalInputs}.`, severityLevels.INFO);
        } else {
             addLog("Analysis complete. No forms or standalone named inputs found.", severityLevels.INFO);
        }

        renderDetectedInputs();

    } catch (error) {
        console.error("Analysis error:", error);
        addLog(`Analysis failed: ${error.message}`, severityLevels.ERROR);
        alert(`Error analyzing URL: ${error.message}\n\nCheck logs for details.`);
    } finally {
        isScanning = false;
        hideLoading();
        updateUIState();
    }
}


/** Renders detected inputs/forms */
function renderDetectedInputs() {
    if (!formsContainer) return;
    formsContainer.innerHTML = ''; // Clear previous

    if (detectedForms.length === 0) {
        formsContainer.innerHTML = '<p class="placeholder">No forms or testable inputs detected.</p>';
        return;
    }

    detectedForms.forEach((form, index) => {
        const formDiv = document.createElement('div');
        formDiv.className = 'form-item';

        const formTitle = form.isPseudoForm
            ? `<i class="fas fa-puzzle-piece"></i> Standalone Inputs (Target: ${escapeHtml(form.action)})`
            : `<i class="fab fa-wpforms"></i> Form ${detectedForms.filter((f, i) => !f.isPseudoForm && i <= index).length} (Action: ${escapeHtml(form.action)}, Method: ${form.method})`;
        const formId = `form-select-${index}`;

        const inputsHtml = (form.inputs && form.inputs.length > 0) // Check if inputs array exists and is not empty
             ? form.inputs.map(input => {
                 const safeInputName = (input.name || `unnamed_${index}`).replace(/[^a-zA-Z0-9_-]/g, '_');
                 const inputId = `input-select-${index}-${safeInputName}-${Math.random().toString(36).substring(2, 7)}`;
                 return `
                 <div class="input-item">
                      <input type="checkbox" id="${inputId}"
                             data-input-type="param-selector"
                             data-form-index="${index}"
                             data-input-name="${escapeHtml(input.name)}"
                             class="input-select-checkbox"
                             title="Select this parameter for testing">
                      <label for="${inputId}" class="input-details">
                          <span class="input-name">${escapeHtml(input.name)}</span>
                          <span class="input-type">(${escapeHtml(input.type)})</span>
                      </label>
                  </div>`;
             }).join('')
             : '<p class="placeholder" style="padding: 5px 0;">No named inputs found in this group.</p>';


        formDiv.innerHTML = `
            <div class="form-header">
                 <input type="checkbox" id="${formId}" data-input-type="form-selector" data-form-index="${index}" class="form-select-checkbox" title="Select/Deselect all inputs in this group">
                 <label for="${formId}" class="form-title">${formTitle}</label>
            </div>
            <div class="form-inputs">${inputsHtml}</div>`;

        formsContainer.appendChild(formDiv);
    });

     selectedInputs = []; // Reset selections
     updateUIState();
}


/** Starts the injection test */
async function startTest() {
    if (isTesting) return;
    if (!ipcRendererAvailable) {
         addLog("Cannot start test: Electron IPC is not available.", severityLevels.ERROR);
         alert("Error: IPC unavailable."); return;
    }
    if (selectedInputs.length === 0) { alert("Please select at least one input parameter to test."); return; }
    if (!currentInjectionType) { alert("Please select a test type (XSS, SQLi, etc.)."); return; } // Added check
    const selectedWordlistFile = wordlistSelect.value;
    if (!selectedWordlistFile) { alert("Please select a payload wordlist."); return; }
    if (!wordlistsDirectory) { alert("Wordlist directory path is not set. Cannot load payloads."); return; }

    // --- Load Payloads ---
    const wordlistPath = path.join(wordlistsDirectory, selectedWordlistFile);
    let currentPayloads;
    try {
        if (!fs || !fs.existsSync(wordlistPath)) throw new Error(`Wordlist file not found: ${selectedWordlistFile}`);
        const rawPayloads = fs.readFileSync(wordlistPath, 'utf8').split(/\r?\n/);
        currentPayloads = rawPayloads.filter(p => p.trim() !== '').map(p => p.trim());
        if (currentPayloads.length === 0) throw new Error("Selected wordlist is empty.");
        payloads[currentInjectionType] = currentPayloads; // Store loaded payloads
        addLog(`Loaded ${currentPayloads.length} payloads from ${selectedWordlistFile}.`, severityLevels.INFO);
        renderPayloads();
    } catch (err) {
        console.error("Error loading wordlist:", err);
        addLog(`Error loading wordlist ${selectedWordlistFile}: ${err.message}`, severityLevels.ERROR);
        alert(`Error loading wordlist: ${err.message}`);
        return;
    }

    // --- Setup Test State ---
    isTesting = true;
    testResults = [];
    resultCounter = 0;
    renderResults();
    updateUIState();
    clearStats();
    startTime = Date.now();
    elapsedTimeInterval = setInterval(updateElapsedTime, 1000);
    abortController = { aborted: false };

    const tasks = []; // Array of { formIndex, inputName, payload }
    selectedInputs.forEach(({ formIndex, inputName }) => {
        currentPayloads.forEach(payload => {
            tasks.push({ formIndex, inputName, payload });
        });
    });

    totalRequests = tasks.length;
    if (totalRequests === 0) {
        addLog("No test requests generated (check selections and payloads).", severityLevels.WARNING);
        isTesting = false;
        updateUIState();
        return;
    }
    updateProgress(0);
    showLoading(`Starting ${currentInjectionType.toUpperCase()} test... (${totalRequests} requests)`);
    addLog(`Starting test (${currentInjectionType.toUpperCase()}) for ${selectedInputs.length} parameters with ${currentPayloads.length} payloads each. Total requests: ${totalRequests}`, severityLevels.INFO);

    // --- Concurrency Control ---
    const concurrency = parseInt(threadsInput.value, 10) || 10;
    let currentTaskIndex = 0;
    let completedRequests = 0;
    activeRequests = 0;
    formsTestedCount = new Set(selectedInputs.map(i => i.formIndex)).size;
    paramsTestedCount = 0; // Reset count

    const runWorker = async () => {
        while (currentTaskIndex < tasks.length) {
            if (abortController.aborted) { break; }

            const taskIndex = currentTaskIndex++;
            if (taskIndex >= tasks.length) break;

            const { formIndex, inputName, payload } = tasks[taskIndex];
            activeRequests++;
            paramsTestedCount++; // Increment as task starts
            updateStats();

            let dataValid = false; // Flag to track if data is okay for IPC call
            let formOrGroup = null;

            try {
                formOrGroup = detectedForms[formIndex];

                // --- Add MORE Defensive Checks ---
                if (!formOrGroup) {
                    addLog(`Data Error: Could not find form/group object for index ${formIndex} (Param: ${inputName})`, severityLevels.ERROR);
                } else if (!formOrGroup.action) {
                    addLog(`Data Error: Missing 'action' URL for form/group index ${formIndex} (Param: ${inputName})`, severityLevels.ERROR);
                } else if (!formOrGroup.method) {
                    addLog(`Data Error: Missing 'method' for form/group index ${formIndex} (Param: ${inputName})`, severityLevels.ERROR);
                } else if (!inputName) {
                     addLog(`Data Error: Missing 'inputName' for form/group index ${formIndex}`, severityLevels.ERROR);
                } else if (typeof payload === 'undefined') {
                     addLog(`Data Error: Payload is undefined for testing param ${inputName} (Form index: ${formIndex})`, severityLevels.ERROR);
                } else if (!formOrGroup.inputs || !Array.isArray(formOrGroup.inputs)) { // <<<--- ADDED CHECK for allParams
                     addLog(`Data Error: Missing or invalid 'inputs' array (for allParams) in form/group index ${formIndex} (Param: ${inputName})`, severityLevels.ERROR);
                }
                 else {
                     dataValid = true; // All checks passed
                 }
                // --- End Defensive Checks ---

                if (dataValid) { // Proceed only if checks passed
                    // Construct args for main process
                    const testArgs = {
                         testType: currentInjectionType, // Checked before loop started
                         targetUrl: formOrGroup.action,
                         method: formOrGroup.method,
                         paramName: inputName,
                         payload: payload,
                         allParams: formOrGroup.inputs, // Checked above
                         testAllParamsTogether: testAllParamsCheckbox.checked,
                         headers: parseHeadersInput(),
                         cookies: parseCookiesInput(),
                         timeout: parseInt(timeoutInput.value, 10) || 5000,
                         followRedirects: followRedirectsCheckbox.checked,
                     };

                    const result = await testParameterIPC(testArgs); // Call IPC function

                    if (result && result.vulnerable) {
                        vulnerabilitiesFound++;
                        addResult({ // Use helper to add result
                             type: currentInjectionType.toUpperCase(),
                             severity: result.severity || severityLevels.MEDIUM,
                             url: result.requestUrl || formOrGroup.action,
                             param: inputName,
                             payload: payload,
                             details: result.details || 'Reflection/Error detected.'
                        });
                    }
                    successfulRequests++;
                } else {
                    // Logged error above, just count as failed
                    failedRequests++;
                    addLog(`Skipping test for param ${inputName || 'unknown'} due to missing/invalid data.`, severityLevels.WARNING);
                }
            } catch (error) {
                // Handle errors from testParameterIPC (IPC errors, main process errors caught and re-thrown)
                 if (!abortController.aborted) {
                     console.error(`Error testing ${inputName || '??'} with payload "${payload === undefined ? '??' : payload}":`, error);
                     // Try to provide context from formOrGroup if available
                     const context = formOrGroup ? ` (Form Action: ${formOrGroup.action})` : '';
                     addLog(`Error testing ${inputName || 'unknown param'}${context}: ${error.message}`, severityLevels.ERROR);
                     failedRequests++;
                 } // Don't log if aborted by user
            } finally {
                 // Ensure progress happens even if skipped or error occurs
                 if (!abortController.aborted) {
                     completedRequests++;
                     activeRequests = Math.max(0, activeRequests - 1); // Decrement active, ensure non-negative
                     updateProgress(Math.round((completedRequests / totalRequests) * 100));
                     updateStats();
                     const delay = parseInt(delayInput.value, 10);
                     if (delay > 0 && !abortController.aborted) {
                         await sleep(delay);
                     }
                 } else {
                      activeRequests = Math.max(0, activeRequests - 1); // Still decrement if aborted mid-task
                      updateStats();
                 }
            }
        } // End while loop
        // addLog(`Worker finished.`, severityLevels.INFO); // Reduce noise
    }; // End runWorker definition

    // Start worker threads
    addLog(`Starting ${concurrency} test workers...`, severityLevels.INFO);
    const workers = Array(concurrency).fill(null).map(() => runWorker());

    try {
        await Promise.all(workers);
    } catch (error) {
        if (!abortController.aborted) {
            console.error("Unexpected error during worker execution:", error);
            addLog(`Unexpected testing error: ${error.message}`, severityLevels.ERROR);
        }
    } finally {
         isTesting = false;
         stopTest(); // Ensure state is reset, timer stopped etc.
         hideLoading();
         if (abortController.aborted) {
             addLog(`Test stopped by user. Completed ${completedRequests}/${totalRequests} requests.`, severityLevels.INFO);
         } else {
             addLog(`Test finished. Total Requests: ${completedRequests}, Successful: ${successfulRequests}, Failed: ${failedRequests}, Vulns Found: ${vulnerabilitiesFound}`, severityLevels.SUCCESS);
         }
         updateUIState();
         if (autoSaveCheckbox.checked && !abortController.aborted && testResults.length > 0) {
              exportResults();
         }
    }
}


/**
 * Wraps the IPC call to send a test request to the main process.
 *
 * @param {object} testArgs - The complete arguments object for the test.
 * @returns {Promise<object|null>} Promise resolving to the result object from main process.
 * @throws {Error} Throws an error if IPC fails or main process returns an error.
 */
async function testParameterIPC(testArgs) {
    if (abortController.aborted) {
        throw new Error('Operation aborted by user.');
    }
    if (!ipcRendererAvailable) {
         throw new Error("IPC is not available to send test request.");
    }

    try {
        // Optional: Log args being sent, can be very verbose
        // console.log("Sending IPC 'send-test-request' with args:", JSON.stringify(testArgs));

        const result = await ipcRenderer.invoke('send-test-request', testArgs);

        // The main process handler should ideally not return null/undefined on success.
        // It should throw an error if something goes wrong internally.
        if (result && result.error) { // Check if main process explicitly returned an error message
             throw new Error(`Main process error: ${result.error}`);
        }
        if (typeof result?.vulnerable === 'undefined') { // Basic check for expected result structure
             console.warn("Received unexpected result structure from 'send-test-request':", result);
             // Decide how to handle - treat as non-vulnerable or throw? Throwing is safer.
             throw new Error("Received unexpected result structure from main process.");
        }
        return result;

    } catch (ipcError) {
         // Catches errors from invoke itself (e.g., handler not found) OR errors thrown by the handler
         console.error(`IPC Error for 'send-test-request' (Param: ${testArgs?.paramName}):`, ipcError);
         // Make the error message clearer that it came from IPC/Main process
         throw new Error(`IPC/Main Process Error: ${ipcError.message}`);
    }
}


/** Stops the current test */
function stopTest() {
    if (abortController && !abortController.aborted) {
        addLog("Stopping test...", severityLevels.INFO);
        abortController.aborted = true;
    }
    if (elapsedTimeInterval) {
        clearInterval(elapsedTimeInterval);
        elapsedTimeInterval = null;
    }
    // isTesting flag is usually set by the caller (startTest finally block)
    // But set it here too just in case stop is called directly
    isTesting = false;
    activeRequests = 0;
    hideLoading();
    updateUIState();
    updateStats();
}

/** Clears results, logs, detected inputs, and resets stats. */
function clearAll() {
    if (isTesting) {
        alert("Cannot clear while testing is in progress. Stop the test first.");
        return;
    }
    testResults = [];
    detectedForms = [];
    selectedInputs = [];
    payloads = {}; // Clear loaded payloads cache
    logContent.innerHTML = '';
    resultCounter = 0;
    renderResults();
    renderDetectedInputs();
    renderPayloads();
    clearStats();
    updateUIState();
    addLog("Cleared results, logs, and detected inputs.", severityLevels.INFO);
}

/** Resets stats counters and updates the display. */
function clearStats() {
    totalRequests = 0;
    successfulRequests = 0;
    failedRequests = 0;
    vulnerabilitiesFound = 0;
    formsTestedCount = 0;
    paramsTestedCount = 0;
    requestsPerSecond = 0;
    activeRequests = 0;
    startTime = 0;
    if (elapsedTimeInterval) {
        clearInterval(elapsedTimeInterval);
        elapsedTimeInterval = null;
    }
    elapsedTimeEl.textContent = "00:00:00";
    updateStats();
    updateProgress(0);
}

/** Exports results using the 'save-results' IPC handler */
function exportResults() {
    if (testResults.length === 0) { alert("No results to export."); return; }
    if (!ipcRendererAvailable) { alert("Export requires Electron IPC."); return; }

    const defaultFileName = `injection_results_${currentInjectionType}_${new Date().toISOString().split('T')[0]}.json`;
    addLog("Attempting to export results...", severityLevels.INFO);

    ipcRenderer.invoke('save-results', { // Use the dedicated handler
        defaultPath: defaultFileName,
        results: testResults,
        format: 'json' // Or make this configurable later
    }).then(filePath => {
        if (filePath && typeof filePath === 'string') {
            addLog(`Results successfully exported to: ${filePath}`, severityLevels.SUCCESS);
            alert(`Results exported to:\n${filePath}`);
        } else {
            // Don't log error if it was just cancelled (filePath is null/undefined)
            if (filePath !== null && typeof filePath !== 'undefined') {
                 addLog(`Export failed or was cancelled.`, severityLevels.WARNING);
            } else {
                 addLog("Result export cancelled by user.", severityLevels.INFO);
            }
        }
    }).catch(err => {
        console.error("Export Error:", err);
        addLog(`Failed to export results: ${err.message}`, severityLevels.ERROR);
        alert(`Failed to export results: ${err.message}`);
    });
}

// --- UI Update Functions ---

/** Updates the enabled/disabled state of UI elements */
function updateUIState() {
    const hasUrl = targetUrlInput.value.trim() !== '';
    const hasSelectedInputs = selectedInputs.length > 0;
    const hasResults = testResults.length > 0;
    const wordlistAvailable = wordlistSelect && !wordlistSelect.disabled && wordlistSelect.value !== '';
    const wordlistSelected = wordlistSelect && wordlistSelect.value !== '';

    analyzeBtn.disabled = !hasUrl || isScanning || isTesting;
    startBtn.disabled = !hasSelectedInputs || !wordlistSelected || isTesting || isScanning || !currentInjectionType;
    stopBtn.disabled = !isTesting;
    clearBtn.disabled = isTesting || (testResults.length === 0 && detectedForms.length === 0 && logContent.children.length <= 1); // Allow clear if only initial log exists
    exportBtn.disabled = !hasResults || isTesting;
    refreshWordlistsBtn.disabled = isScanning || isTesting || !wordlistsDirectory;

    targetUrlInput.disabled = isScanning || isTesting;
    wordlistSelect.disabled = isScanning || isTesting || !wordlistsDirectory; // Keep disabled if dir unknown
    threadsInput.disabled = isTesting;
    timeoutInput.disabled = isTesting;
    delayInput.disabled = isTesting;
    followRedirectsCheckbox.disabled = isScanning || isTesting;
    autoSaveCheckbox.disabled = isTesting;
    testAllParamsCheckbox.disabled = isTesting;
    headersTextarea.disabled = isScanning || isTesting;
    cookiesTextarea.disabled = isScanning || isTesting;

    testTypeButtons?.querySelectorAll('button').forEach(btn => btn.disabled = isScanning || isTesting);
    formsContainer?.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.disabled = isTesting || isScanning);
}

/** Displays the loading overlay */
function showLoading(text = "Loading...") {
    if (!loadingOverlay || !loadingText) return;
    loadingText.textContent = text;
    loadingOverlay.style.display = "flex";
}

/** Hides the loading overlay */
function hideLoading() {
     if (!loadingOverlay) return;
    loadingOverlay.style.display = "none";
}

/** Updates the progress bar and text */
function updateProgress(percentage) {
     if (!progressBar || !progressText) return;
    const clampedPercentage = Math.max(0, Math.min(100, percentage));
    progressBar.style.width = `${clampedPercentage}%`;
    progressText.textContent = `${Math.round(clampedPercentage)}%`;
}

/** Updates the statistics display area */
function updateStats() {
    totalRequestsEl.textContent = totalRequests;
    formsTestedEl.textContent = formsTestedCount;
    paramsTestedEl.textContent = paramsTestedCount;
    vulnsFoundEl.textContent = vulnerabilitiesFound;

    const now = Date.now();
    const elapsedSeconds = startTime > 0 ? (now - startTime) / 1000 : 0;
    if (elapsedSeconds > 0.1) { // Avoid division by zero or tiny fractions
        const completed = successfulRequests + failedRequests;
        requestsPerSecond = Math.round(completed / elapsedSeconds);
    } else {
        requestsPerSecond = 0;
    }
    requestsPerSecondEl.textContent = requestsPerSecond;
}

/** Updates the elapsed time display every second */
function updateElapsedTime() {
    if (!startTime) return;
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(elapsed / 3600);
    const minutes = Math.floor((elapsed % 3600) / 60);
    const seconds = elapsed % 60;
    elapsedTimeEl.textContent = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    updateStats(); // Update RPS which depends on time
}

/** Adds a log entry to the log UI */
function addLog(message, level = severityLevels.INFO) {
    if (!logContent) return;
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement("div");
    logEntry.classList.add("log-entry", `severity-${level.toLowerCase()}`); // Add severity class

    logEntry.innerHTML = `
        <span class="log-timestamp">${timestamp}</span>
        <span class="log-severity">${level}</span>
        <span class="log-message">${escapeHtml(message)}</span>
    `;
    logContent.appendChild(logEntry);
    logContent.scrollTop = logContent.scrollHeight; // Auto-scroll
}

/** Adds a result object to the results array and updates the UI table */
function addResult(result) {
    result.id = ++resultCounter;
    result.timestamp = result.timestamp || Date.now();
    testResults.push(result);
    renderResults();
    updateStats(); // Update vuln count
}

/** Renders the current test results into the results table, applying filters */
function renderResults() {
    if (!resultsBody) return;

    const searchTerm = filterResultsInput.value.toLowerCase();
    const selectedType = filterTypeSelect.value; // Already uppercase from options or ""
    const selectedSeverity = filterSeveritySelect.value;

    const filteredResults = testResults.filter(r => {
        const typeMatch = !selectedType || r.type.toUpperCase() === selectedType;
        const severityMatch = !selectedSeverity || r.severity === selectedSeverity;
        const searchMatch = !searchTerm ||
                              (r.url && r.url.toLowerCase().includes(searchTerm)) ||
                              (r.param && r.param.toLowerCase().includes(searchTerm)) ||
                              (r.payload && r.payload.toLowerCase().includes(searchTerm)) ||
                              (r.details && r.details.toLowerCase().includes(searchTerm));
        return typeMatch && severityMatch && searchMatch;
    });

    filteredResults.sort((a, b) => b.id - a.id); // Sort newest first

    resultsBody.innerHTML = filteredResults.map(result => `
        <tr class="severity-row-${result.severity.toLowerCase()}" onclick="showResultDetails(${result.id})">
            <td>${result.id}</td>
            <td>${new Date(result.timestamp).toLocaleTimeString()}</td>
            <td>${escapeHtml(result.type)}</td>
            <td class="severity-${result.severity.toLowerCase()}">${escapeHtml(result.severity)}</td>
            <td class="url-cell" title="${escapeHtml(result.url)}">${escapeHtml(truncateString(result.url))}</td>
            <td title="${escapeHtml(result.param)}">${escapeHtml(truncateString(result.param, 30))}</td>
            <td class="payload-cell" title="${escapeHtml(result.payload)}">${escapeHtml(truncateString(result.payload))}</td>
            <td class="details-cell" title="${escapeHtml(result.details)}">${escapeHtml(truncateString(result.details))}</td>
        </tr>
    `).join('');

    if (testResults.length > 0 && filteredResults.length === 0) {
         resultsBody.innerHTML = `<tr><td colspan="8" class="placeholder">No results match the current filter.</td></tr>`;
    } else if (testResults.length === 0) {
         resultsBody.innerHTML = `<tr><td colspan="8" class="placeholder">No results yet. Start a test.</td></tr>`;
    }
}

// Basic function to show more details (e.g., in a modal or separate area - not implemented)
function showResultDetails(resultId) {
    const result = testResults.find(r => r.id === resultId);
    if(result) {
        console.log("Selected Result Details:", result);
        alert(`Result ID: ${result.id}\nType: ${result.type}\nSeverity: ${result.severity}\nParam: ${result.param}\nURL: ${result.url}\nPayload: ${result.payload}\nDetails: ${result.details}`);
    }
}


/** Renders the loaded payloads for the current test type */
function renderPayloads() {
     if (!payloadsContainer) return;
     const currentPayloads = payloads[currentInjectionType] || [];

     if (currentPayloads.length > 0) {
         payloadsContainer.innerHTML = currentPayloads.map(p => `<div>${escapeHtml(p)}</div>`).join('');
     } else {
         payloadsContainer.innerHTML = '<p class="placeholder">Select a wordlist for the chosen test type.</p>';
     }
}


// --- Wordlist Handling ---

/** Loads available .txt wordlists from the determined directory */
function loadWordlists() {
    if (!isElectron || !fs || !path || !wordlistsDirectory) {
        addLog("Cannot load wordlists: Environment requirements not met (Electron/Node.js modules missing or directory path unset).", severityLevels.WARNING);
        disableWordlistUI();
        return;
    }

    addLog(`Loading wordlists for type '${currentInjectionType}' from: ${wordlistsDirectory}`, severityLevels.INFO);
    wordlistSelect.innerHTML = '<option value="">Loading...</option>';
    wordlistSelect.disabled = true; // Disable while loading

    try {
        if (!fs.existsSync(wordlistsDirectory)) {
             throw new Error(`Directory not found: ${wordlistsDirectory}`);
        }

        const files = fs.readdirSync(wordlistsDirectory);
        // Filter for .txt files and optionally match the currentInjectionType in the filename
        const txtFiles = files.filter(file => {
             const lowerFile = file.toLowerCase();
             return lowerFile.endsWith('.txt'); // && lowerFile.includes(currentInjectionType); // Make type matching optional?
        });
        // Prioritize files matching the current type
        const typeSpecificFiles = txtFiles.filter(f => f.toLowerCase().includes(currentInjectionType));
        const otherFiles = txtFiles.filter(f => !typeSpecificFiles.includes(f));

        wordlistSelect.innerHTML = '<option value="">Select wordlist...</option>'; // Default empty

        if (typeSpecificFiles.length === 0 && otherFiles.length === 0) {
            wordlistSelect.innerHTML = `<option value="">No .txt lists found</option>`;
            addLog(`No .txt wordlist files found in directory.`, severityLevels.WARNING);
        } else {
             typeSpecificFiles.forEach(file => {
                 wordlistSelect.innerHTML += `<option value="${escapeHtml(file)}">${escapeHtml(file)}</option>`;
             });
             if (typeSpecificFiles.length > 0 && otherFiles.length > 0) {
                  wordlistSelect.innerHTML += `<option disabled>--- Other Lists ---</option>`;
             }
             otherFiles.forEach(file => {
                 wordlistSelect.innerHTML += `<option value="${escapeHtml(file)}">${escapeHtml(file)}</option>`;
             });
            addLog(`Found ${txtFiles.length} total .txt wordlist(s). Displayed type-specific lists first.`, severityLevels.INFO);
        }

    } catch (error) {
        console.error("Error loading wordlists:", error);
        addLog(`Error loading wordlists: ${error.message}`, severityLevels.ERROR);
        wordlistSelect.innerHTML = '<option value="">Error loading</option>';
    } finally {
         // Re-enable select only if not testing/scanning and directory is known
         wordlistSelect.disabled = isTesting || isScanning || !wordlistsDirectory;
         updateUIState(); // Update start button state etc.
    }
}


// --- Utility Functions ---

/** Basic HTML escaping */
function escapeHtml(unsafe) {
    if (unsafe === null || typeof unsafe === 'undefined') return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

/** Validates if a string is a valid HTTP/HTTPS URL */
function isValidHttpUrl(string) {
  let url;
  try { url = new URL(string); }
  catch (_) { return false; }
  return url.protocol === "http:" || url.protocol === "https:";
}

/** Pauses execution for a specified time */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Truncates string for display */
function truncateString(str, maxLength = 50) {
    if (typeof str !== 'string') return str;
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + "...";
}

/** Parses the headers textarea into an object */
function parseHeadersInput() {
    const headers = {};
    const lines = headersTextarea.value.split('\n');
    lines.forEach(line => {
        const parts = line.match(/^([^:]+):\s*(.*)$/); // Match key: value
        if (parts && parts.length === 3) {
            const key = parts[1].trim();
            const value = parts[2].trim();
            if (key && value) {
                // Overwrite duplicates (last one wins) - handle multi-value headers if needed
                headers[key] = value;
            }
        }
    });
    return headers;
}

/** Parses the cookies textarea into an object with a 'Cookie' property */
function parseCookiesInput() {
     // Returns object like { 'Cookie': 'name1=value1; name2=value2' }
     const cookieString = cookiesTextarea.value.trim().replace(/\n/g, '; ').replace(/\s*;\s*/g, '; '); // Normalize separators
     if (cookieString) {
        return { 'Cookie': cookieString }; // Wrap in object expected by main handler args
     }
     return {}; // Return empty object if no cookies
}