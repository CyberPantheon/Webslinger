const { ipcRenderer } = require("electron");

document.addEventListener("DOMContentLoaded", () => {
  // Window controls
  const minimizeBtn = document.getElementById("minimize-btn");
  if (minimizeBtn) minimizeBtn.addEventListener("click", () => ipcRenderer.send("minimize-window"));
  const closeBtn = document.getElementById("close-btn");
  if (closeBtn) closeBtn.addEventListener("click", () => ipcRenderer.send("close-window"));
  const maximizeBtn = document.getElementById('maximize-btn');
  if (maximizeBtn && window.electronAPI) {
    maximizeBtn.addEventListener('click', () => {
      window.electronAPI.toggleMaximizeWindow && window.electronAPI.toggleMaximizeWindow();
    });
  } else if (maximizeBtn && typeof require === 'function') {
    // Fallback for preload-less Electron
    maximizeBtn.addEventListener('click', () => {
      ipcRenderer.send('toggle-maximize-window');
    });
  }

  // Tab switching (future: support multiple spiders)
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelector(".tab-btn.active")?.classList.remove("active");
      button.classList.add("active");
      const targetTab = button.getAttribute("data-tab");
      tabPanes.forEach((pane) => {
        pane.classList.toggle("active", pane.id === targetTab);
      });
    });
  });

  // Spider toggles: switch between XSS, SQLi, IDOR, Open Redirect, CSRF, Clickjacking, CORS, and Subdomain Takeover settings/tabs
  const xssToggle = document.getElementById("xss-spider-toggle");
  const sqliToggle = document.getElementById("sqli-spider-toggle");
  const idorToggle = document.getElementById("idor-spider-toggle");
  const openredirectToggle = document.getElementById("openredirect-spider-toggle");
  const csrfToggle = document.getElementById("csrf-spider-toggle");
  const clickjackingToggle = document.getElementById("clickjacking-spider-toggle");
  const corsToggle = document.getElementById("cors-spider-toggle");
  const subdomainToggle = document.getElementById("subdomain-spider-toggle");
  const xssSettings = document.getElementById("xss-spider-settings");
  const sqliSettings = document.getElementById("sqli-spider-settings");
  const idorSettings = document.getElementById("idor-spider-settings");
  const openredirectSettings = document.getElementById("openredirect-spider-settings");
  const csrfSettings = document.getElementById("csrf-spider-settings");
  const clickjackingSettings = document.getElementById("clickjacking-spider-settings");
  const corsSettings = document.getElementById("cors-spider-settings");
  const subdomainSettings = document.getElementById("subdomain-spider-settings");
  const xssTab = document.getElementById("xss-spider-tab");
  const sqliTab = document.getElementById("sqli-spider-tab");
  const idorTab = document.getElementById("idor-spider-tab");
  const openredirectTab = document.getElementById("openredirect-spider-tab");
  const csrfTab = document.getElementById("csrf-spider-tab");
  const clickjackingTab = document.getElementById("clickjacking-spider-tab");
  const corsTab = document.getElementById("cors-spider-tab");
  const subdomainTab = document.getElementById("subdomain-spider-tab");
  const xssTabBtn = document.querySelector('[data-tab="xss-spider-tab"]');
  const sqliTabBtn = document.querySelector('[data-tab="sqli-spider-tab"]');
  const idorTabBtn = document.querySelector('[data-tab="idor-spider-tab"]');
  const openredirectTabBtn = document.querySelector('[data-tab="openredirect-spider-tab"]');
  const csrfTabBtn = document.querySelector('[data-tab="csrf-spider-tab"]');
  const clickjackingTabBtn = document.querySelector('[data-tab="clickjacking-spider-tab"]');
  const corsTabBtn = document.querySelector('[data-tab="cors-spider-tab"]');
  const subdomainTabBtn = document.querySelector('[data-tab="subdomain-spider-tab"]');
  const wordpressreconToggle = document.getElementById("wordpressrecon-spider-toggle");
  const wordpressreconSettings = document.getElementById("wordpressrecon-spider-settings");
  const wordpressreconTab = document.getElementById("wordpressrecon-spider-tab");
  const wordpressreconTabBtn = document.querySelector('[data-tab="wordpressrecon-spider-tab"]');

  function showXss() {
    xssSettings.style.display = "flex";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.add("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.add("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = true;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showSqli() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "flex";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.add("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.add("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = true;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showIdor() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "flex";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.add("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.add("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = true;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showOpenRedirect() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "flex";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.add("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.add("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = true;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showCsrf() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "flex";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.add("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.add("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = true;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showClickjacking() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "flex";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.add("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.add("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = true;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showCors() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "flex";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.add("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.add("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = true;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = false;
  }
  function showSubdomain() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "flex";
    wordpressreconSettings.style.display = "none";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.add("active");
    wordpressreconTab.classList.remove("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.add("active");
    wordpressreconTabBtn.classList.remove("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = true;
    wordpressreconToggle.checked = false;
  }
  function showWordpressRecon() {
    xssSettings.style.display = "none";
    sqliSettings.style.display = "none";
    idorSettings.style.display = "none";
    openredirectSettings.style.display = "none";
    csrfSettings.style.display = "none";
    clickjackingSettings.style.display = "none";
    corsSettings.style.display = "none";
    subdomainSettings.style.display = "none";
    wordpressreconSettings.style.display = "flex";
    xssTab.classList.remove("active");
    sqliTab.classList.remove("active");
    idorTab.classList.remove("active");
    openredirectTab.classList.remove("active");
    csrfTab.classList.remove("active");
    clickjackingTab.classList.remove("active");
    corsTab.classList.remove("active");
    subdomainTab.classList.remove("active");
    wordpressreconTab.classList.add("active");
    xssTabBtn.classList.remove("active");
    sqliTabBtn.classList.remove("active");
    idorTabBtn.classList.remove("active");
    openredirectTabBtn.classList.remove("active");
    csrfTabBtn.classList.remove("active");
    clickjackingTabBtn.classList.remove("active");
    corsTabBtn.classList.remove("active");
    subdomainTabBtn.classList.remove("active");
    wordpressreconTabBtn.classList.add("active");
    xssToggle.checked = false;
    sqliToggle.checked = false;
    idorToggle.checked = false;
    openredirectToggle.checked = false;
    csrfToggle.checked = false;
    clickjackingToggle.checked = false;
    corsToggle.checked = false;
    subdomainToggle.checked = false;
    wordpressreconToggle.checked = true;
  }
  xssToggle.addEventListener("change", () => { if (xssToggle.checked) showXss(); });
  sqliToggle.addEventListener("change", () => { if (sqliToggle.checked) showSqli(); });
  idorToggle.addEventListener("change", () => { if (idorToggle.checked) showIdor(); });
  openredirectToggle.addEventListener("change", () => { if (openredirectToggle.checked) showOpenRedirect(); });
  csrfToggle.addEventListener("change", () => { if (csrfToggle.checked) showCsrf(); });
  clickjackingToggle.addEventListener("change", () => { if (clickjackingToggle.checked) showClickjacking(); });
  corsToggle.addEventListener("change", () => { if (corsToggle.checked) showCors(); });
  subdomainToggle.addEventListener("change", () => { if (subdomainToggle.checked) showSubdomain(); });
  wordpressreconToggle.addEventListener("change", () => { if (wordpressreconToggle.checked) showWordpressRecon(); });
  xssTabBtn.addEventListener("click", showXss);
  sqliTabBtn.addEventListener("click", showSqli);
  idorTabBtn.addEventListener("click", showIdor);
  openredirectTabBtn.addEventListener("click", showOpenRedirect);
  csrfTabBtn.addEventListener("click", showCsrf);
  clickjackingTabBtn.addEventListener("click", showClickjacking);
  corsTabBtn.addEventListener("click", showCors);
  subdomainTabBtn.addEventListener("click", showSubdomain);
  wordpressreconTabBtn.addEventListener("click", showWordpressRecon);

  // XSS Spider controls
  const xssForm = document.getElementById("xss-spider-form");
  const xssStartBtn = document.getElementById("xss-start-btn");
  const xssStopBtn = document.getElementById("xss-stop-btn");
  const xssStatus = document.getElementById("xss-status").querySelector("span");
  const xssProgress = document.getElementById("xss-progress").querySelector("span");
  const xssFound = document.getElementById("xss-found").querySelector("span");
  const xssLog = document.getElementById("xss-spider-log");
  const xssFindingsBody = document.getElementById("xss-findings-body");

  let spiderRunning = false;

  xssForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (spiderRunning) return;
    const url = document.getElementById("xss-start-url").value.trim();
    const depth = parseInt(document.getElementById("xss-depth").value, 10);
    const sameDomain = document.getElementById("xss-same-domain").checked;
    const followForms = document.getElementById("xss-follow-forms").checked;
    const domXss = document.getElementById("xss-dom-xss").checked;
    const smartMode = document.getElementById("xss-smart-mode").checked;
    const payloadSet = document.getElementById("xss-payload-set").value;
    const threads = parseInt(document.getElementById("xss-threads").value, 10);
    // Clear log and findings
    xssLog.innerHTML = '';
    xssFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    xssStatus.textContent = 'Running';
    xssStatus.className = 'status-running';
    xssProgress.textContent = '0';
    xssFound.textContent = '0';
    xssStartBtn.disabled = true;
    xssStopBtn.disabled = false;
    spiderRunning = true;
    // Send start command to backend
    ipcRenderer.send('xss-spider:start', {
      url, depth, sameDomain, followForms, domXss, smartMode, payloadSet, threads
    });
    appendXssLog('Started XSS Spider on ' + url, 'action');
  });

  xssStopBtn.addEventListener("click", () => {
    if (!spiderRunning) return;
    ipcRenderer.send('xss-spider:stop');
    appendXssLog('Stopping XSS Spider...', 'action');
    xssStatus.textContent = 'Stopping...';
    xssStatus.className = 'status-stopping';
    xssStopBtn.disabled = true;
  });

  // IPC listeners for log, progress, findings, status
  ipcRenderer.on('xss-spider:log', (event, msg, type = 'info') => {
    appendXssLog(msg, type);
  });
  ipcRenderer.on('xss-spider:progress', (event, progress) => {
    xssProgress.textContent = progress;
  });
  ipcRenderer.on('xss-spider:found', (event, count) => {
    xssFound.textContent = count;
  });
  ipcRenderer.on('xss-spider:status', (event, status) => {
    xssStatus.textContent = status;
    xssStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      xssStartBtn.disabled = false;
      xssStopBtn.disabled = true;
      spiderRunning = false;
    }
  });
  ipcRenderer.on('xss-spider:finding', (event, finding) => {
    addFinding(finding);
  });
  ipcRenderer.on('xss-spider:clear', () => {
    xssLog.innerHTML = '';
    xssFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    xssProgress.textContent = '0';
    xssFound.textContent = '0';
  });

  function appendXssLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    xssLog.appendChild(entry);
    xssLog.scrollTop = xssLog.scrollHeight;
  }

  function addFinding(finding) {
    // Remove placeholder if present
    if (xssFindingsBody.querySelector('.placeholder')) xssFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.parameter || ''}</td>
      <td>${finding.payload || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    xssFindingsBody.appendChild(tr);
  }

  // SQLi Spider controls
  const sqliForm = document.getElementById("sqli-spider-form");
  const sqliStartBtn = document.getElementById("sqli-start-btn");
  const sqliStopBtn = document.getElementById("sqli-stop-btn");
  const sqliStatus = document.getElementById("sqli-status").querySelector("span");
  const sqliProgress = document.getElementById("sqli-progress").querySelector("span");
  const sqliFound = document.getElementById("sqli-found").querySelector("span");
  const sqliLog = document.getElementById("sqli-spider-log");
  const sqliFindingsBody = document.getElementById("sqli-findings-body");
  const sqliPayloadSet = document.getElementById("sqli-payload-set");
  const sqliPayloadFile = document.getElementById("sqli-payload-file");
  const sqliPayloadBrowse = document.getElementById("sqli-payload-browse");

  let sqliSpiderRunning = false;
  let sqliPayloadFilePath = null;

  sqliPayloadBrowse.addEventListener("click", () => {
    sqliPayloadFile.click();
  });
  sqliPayloadFile.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      sqliPayloadFilePath = e.target.files[0].path;
      let opt = document.createElement("option");
      opt.value = sqliPayloadFilePath;
      opt.textContent = e.target.files[0].name;
      sqliPayloadSet.appendChild(opt);
      sqliPayloadSet.value = sqliPayloadFilePath;
    }
  });

  sqliForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (sqliSpiderRunning) return;
    const url = document.getElementById("sqli-start-url").value.trim();
    const payloadSet = sqliPayloadSet.value;
    const threads = parseInt(document.getElementById("sqli-threads").value, 10);
    const errorBased = document.getElementById("sqli-error-based").checked;
    const booleanBased = document.getElementById("sqli-boolean-based").checked;
    const timeBased = document.getElementById("sqli-time-based").checked;
    const unionBased = document.getElementById("sqli-union-based").checked;
    const oob = document.getElementById("sqli-oob").checked;
    const headerInjection = document.getElementById("sqli-header-injection").checked;
    const advancedMode = document.getElementById("sqli-advanced-mode").checked;
    // Clear log and findings
    sqliLog.innerHTML = '';
    sqliFindingsBody.innerHTML = '<tr><td colspan="7" class="placeholder">No findings yet.</td></tr>';
    sqliStatus.textContent = 'Running';
    sqliStatus.className = 'status-running';
    sqliProgress.textContent = '0';
    sqliFound.textContent = '0';
    sqliStartBtn.disabled = true;
    sqliStopBtn.disabled = false;
    sqliSpiderRunning = true;
    ipcRenderer.send('sqli-spider:start', {
      url, payloadSet, threads, errorBased, booleanBased, timeBased, unionBased, oob, headerInjection, advancedMode
    });
    appendSqliLog('Started SQLi Spider on ' + url, 'action');
  });
  sqliStopBtn.addEventListener("click", () => {
    if (!sqliSpiderRunning) return;
    ipcRenderer.send('sqli-spider:stop');
    appendSqliLog('Stopping SQLi Spider...', 'action');
    sqliStatus.textContent = 'Stopping...';
    sqliStatus.className = 'status-stopping';
    sqliStopBtn.disabled = true;
  });
  ipcRenderer.on('sqli-spider:log', (event, msg, type = 'info') => {
    appendSqliLog(msg, type);
  });
  ipcRenderer.on('sqli-spider:progress', (event, progress) => {
    sqliProgress.textContent = progress;
  });
  ipcRenderer.on('sqli-spider:found', (event, count) => {
    sqliFound.textContent = count;
  });
  ipcRenderer.on('sqli-spider:status', (event, status) => {
    sqliStatus.textContent = status;
    sqliStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      sqliStartBtn.disabled = false;
      sqliStopBtn.disabled = true;
      sqliSpiderRunning = false;
    }
  });
  ipcRenderer.on('sqli-spider:finding', (event, finding) => {
    addSqliFinding(finding);
  });
  ipcRenderer.on('sqli-spider:clear', () => {
    sqliLog.innerHTML = '';
    sqliFindingsBody.innerHTML = '<tr><td colspan="7" class="placeholder">No findings yet.</td></tr>';
    sqliProgress.textContent = '0';
    sqliFound.textContent = '0';
  });
  function appendSqliLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    sqliLog.appendChild(entry);
    sqliLog.scrollTop = sqliLog.scrollHeight;
  }
  function addSqliFinding(finding) {
    if (sqliFindingsBody.querySelector('.placeholder')) sqliFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.parameter || ''}</td>
      <td>${finding.payload || ''}</td>
      <td>${finding.technique || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    sqliFindingsBody.appendChild(tr);
  }

  // IDOR Spider controls
  const idorForm = document.getElementById("idor-spider-form");
  const idorStartBtn = document.getElementById("idor-start-btn");
  const idorStopBtn = document.getElementById("idor-stop-btn");
  const idorStatus = document.getElementById("idor-status").querySelector("span");
  const idorProgress = document.getElementById("idor-progress").querySelector("span");
  const idorFound = document.getElementById("idor-found").querySelector("span");
  const idorLog = document.getElementById("idor-spider-log");
  const idorFindingsBody = document.getElementById("idor-findings-body");

  let idorSpiderRunning = false;

  idorForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (idorSpiderRunning) return;
    const url = document.getElementById("idor-start-url").value.trim();
    const depth = parseInt(document.getElementById("idor-depth").value, 10);
    const sameDomain = document.getElementById("idor-same-domain").checked;
    const fuzzParams = document.getElementById("idor-fuzz-params").checked;
    const enumSubdomains = document.getElementById("idor-enum-subdomains").checked;
    const smartMode = document.getElementById("idor-smart-mode").checked;
    const threads = parseInt(document.getElementById("idor-threads").value, 10);
    // Clear log and findings
    idorLog.innerHTML = '';
    idorFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    idorStatus.textContent = 'Running';
    idorStatus.className = 'status-running';
    idorProgress.textContent = '0';
    idorFound.textContent = '0';
    idorStartBtn.disabled = true;
    idorStopBtn.disabled = false;
    idorSpiderRunning = true;
    ipcRenderer.send('idor-spider:start', {
      url, depth, sameDomain, fuzzParams, enumSubdomains, smartMode, threads
    });
    appendIdorLog('Started IDOR Spider on ' + url, 'action');
  });

  idorStopBtn.addEventListener("click", () => {
    if (!idorSpiderRunning) return;
    ipcRenderer.send('idor-spider:stop');
    appendIdorLog('Stopping IDOR Spider...', 'action');
    idorStatus.textContent = 'Stopping...';
    idorStatus.className = 'status-stopping';
    idorStopBtn.disabled = true;
  });

  ipcRenderer.on('idor-spider:log', (event, msg, type = 'info') => {
    appendIdorLog(msg, type);
  });
  ipcRenderer.on('idor-spider:progress', (event, progress) => {
    idorProgress.textContent = progress;
  });
  ipcRenderer.on('idor-spider:found', (event, count) => {
    idorFound.textContent = count;
  });
  ipcRenderer.on('idor-spider:status', (event, status) => {
    idorStatus.textContent = status;
    idorStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      idorStartBtn.disabled = false;
      idorStopBtn.disabled = true;
      idorSpiderRunning = false;
    }
  });
  ipcRenderer.on('idor-spider:finding', (event, finding) => {
    addIdorFinding(finding);
  });
  ipcRenderer.on('idor-spider:clear', () => {
    idorLog.innerHTML = '';
    idorFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    idorProgress.textContent = '0';
    idorFound.textContent = '0';
  });

  function appendIdorLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    idorLog.appendChild(entry);
    idorLog.scrollTop = idorLog.scrollHeight;
  }

  function addIdorFinding(finding) {
    if (idorFindingsBody.querySelector('.placeholder')) idorFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.parameter || ''}</td>
      <td>${finding.payload || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    idorFindingsBody.appendChild(tr);
  }

  // Open Redirect Spider controls
  const openredirectForm = document.getElementById("openredirect-spider-form");
  const openredirectStartBtn = document.getElementById("openredirect-start-btn");
  const openredirectStopBtn = document.getElementById("openredirect-stop-btn");
  const openredirectStatus = document.getElementById("openredirect-status").querySelector("span");
  const openredirectProgress = document.getElementById("openredirect-progress").querySelector("span");
  const openredirectFound = document.getElementById("openredirect-found").querySelector("span");
  const openredirectLog = document.getElementById("openredirect-spider-log");
  const openredirectFindingsBody = document.getElementById("openredirect-findings-body");

  let openredirectSpiderRunning = false;

  openredirectForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (openredirectSpiderRunning) return;
    const urls = document.getElementById("openredirect-start-urls").value
      .split('\n').map(u => u.trim()).filter(Boolean);
    const depth = parseInt(document.getElementById("openredirect-depth").value, 10);
    const sameDomain = document.getElementById("openredirect-same-domain").checked;
    const smartMode = document.getElementById("openredirect-smart-mode").checked;
    const threads = parseInt(document.getElementById("openredirect-threads").value, 10);
    // Clear log and findings
    openredirectLog.innerHTML = '';
    openredirectFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    openredirectStatus.textContent = 'Running';
    openredirectStatus.className = 'status-running';
    openredirectProgress.textContent = '0';
    openredirectFound.textContent = '0';
    openredirectStartBtn.disabled = true;
    openredirectStopBtn.disabled = false;
    openredirectSpiderRunning = true;
    ipcRenderer.send('openredirect-spider:start', {
      urls, depth, sameDomain, smartMode, threads
    });
    appendOpenRedirectLog('Started Open Redirect Spider on ' + urls.join(', '), 'action');
  });

  openredirectStopBtn.addEventListener("click", () => {
    if (!openredirectSpiderRunning) return;
    ipcRenderer.send('openredirect-spider:stop');
    appendOpenRedirectLog('Stopping Open Redirect Spider...', 'action');
    openredirectStatus.textContent = 'Stopping...';
    openredirectStatus.className = 'status-stopping';
    openredirectStopBtn.disabled = true;
  });

  ipcRenderer.on('openredirect-spider:log', (event, msg, type = 'info') => {
    appendOpenRedirectLog(msg, type);
  });
  ipcRenderer.on('openredirect-spider:progress', (event, progress) => {
    openredirectProgress.textContent = progress;
  });
  ipcRenderer.on('openredirect-spider:found', (event, count) => {
    openredirectFound.textContent = count;
  });
  ipcRenderer.on('openredirect-spider:status', (event, status) => {
    openredirectStatus.textContent = status;
    openredirectStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      openredirectStartBtn.disabled = false;
      openredirectStopBtn.disabled = true;
      openredirectSpiderRunning = false;
    }
  });
  ipcRenderer.on('openredirect-spider:finding', (event, finding) => {
    addOpenRedirectFinding(finding);
  });
  ipcRenderer.on('openredirect-spider:clear', () => {
    openredirectLog.innerHTML = '';
    openredirectFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    openredirectProgress.textContent = '0';
    openredirectFound.textContent = '0';
  });

  function appendOpenRedirectLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    openredirectLog.appendChild(entry);
    openredirectLog.scrollTop = openredirectLog.scrollHeight;
  }

  function addOpenRedirectFinding(finding) {
    if (openredirectFindingsBody.querySelector('.placeholder')) openredirectFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.parameter || ''}</td>
      <td>${finding.payload || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    openredirectFindingsBody.appendChild(tr);
  }

  // CSRF Spider controls
  const csrfForm = document.getElementById("csrf-spider-form");
  const csrfStartBtn = document.getElementById("csrf-start-btn");
  const csrfStopBtn = document.getElementById("csrf-stop-btn");
  const csrfStatus = document.getElementById("csrf-status").querySelector("span");
  const csrfProgress = document.getElementById("csrf-progress").querySelector("span");
  const csrfFound = document.getElementById("csrf-found").querySelector("span");
  const csrfLog = document.getElementById("csrf-spider-log");
  const csrfFindingsBody = document.getElementById("csrf-findings-body");

  let csrfSpiderRunning = false;

  csrfForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (csrfSpiderRunning) return;
    const urls = document.getElementById("csrf-start-urls").value
      .split('\n').map(u => u.trim()).filter(Boolean);
    const depth = parseInt(document.getElementById("csrf-depth").value, 10);
    const sameDomain = document.getElementById("csrf-same-domain").checked;
    const smartMode = document.getElementById("csrf-smart-mode").checked;
    const threads = parseInt(document.getElementById("csrf-threads").value, 10);
    // Clear log and findings
    csrfLog.innerHTML = '';
    csrfFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    csrfStatus.textContent = 'Running';
    csrfStatus.className = 'status-running';
    csrfProgress.textContent = '0';
    csrfFound.textContent = '0';
    csrfStartBtn.disabled = true;
    csrfStopBtn.disabled = false;
    csrfSpiderRunning = true;
    ipcRenderer.send('csrf-spider:start', {
      urls, depth, sameDomain, smartMode, threads
    });
    appendCsrfLog('Started CSRF Spider on ' + urls.join(', '), 'action');
  });

  csrfStopBtn.addEventListener("click", () => {
    if (!csrfSpiderRunning) return;
    ipcRenderer.send('csrf-spider:stop');
    appendCsrfLog('Stopping CSRF Spider...', 'action');
    csrfStatus.textContent = 'Stopping...';
    csrfStatus.className = 'status-stopping';
    csrfStopBtn.disabled = true;
  });

  ipcRenderer.on('csrf-spider:log', (event, msg, type = 'info') => {
    appendCsrfLog(msg, type);
  });
  ipcRenderer.on('csrf-spider:progress', (event, progress) => {
    csrfProgress.textContent = progress;
  });
  ipcRenderer.on('csrf-spider:found', (event, count) => {
    csrfFound.textContent = count;
  });
  ipcRenderer.on('csrf-spider:status', (event, status) => {
    csrfStatus.textContent = status;
    csrfStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      csrfStartBtn.disabled = false;
      csrfStopBtn.disabled = true;
      csrfSpiderRunning = false;
    }
  });
  ipcRenderer.on('csrf-spider:finding', (event, finding) => {
    addCsrfFinding(finding);
  });
  ipcRenderer.on('csrf-spider:clear', () => {
    csrfLog.innerHTML = '';
    csrfFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    csrfProgress.textContent = '0';
    csrfFound.textContent = '0';
  });

  function appendCsrfLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    csrfLog.appendChild(entry);
    csrfLog.scrollTop = csrfLog.scrollHeight;
  }

  function addCsrfFinding(finding) {
    if (csrfFindingsBody.querySelector('.placeholder')) csrfFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.formAction || ''}</td>
      <td>${finding.tokenField || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    csrfFindingsBody.appendChild(tr);
  }

  // Clickjacking Spider controls
  const clickjackingForm = document.getElementById("clickjacking-spider-form");
  const clickjackingStartBtn = document.getElementById("clickjacking-start-btn");
  const clickjackingStopBtn = document.getElementById("clickjacking-stop-btn");
  const clickjackingStatus = document.getElementById("clickjacking-status").querySelector("span");
  const clickjackingProgress = document.getElementById("clickjacking-progress").querySelector("span");
  const clickjackingFound = document.getElementById("clickjacking-found").querySelector("span");
  const clickjackingLog = document.getElementById("clickjacking-spider-log");
  const clickjackingFindingsBody = document.getElementById("clickjacking-findings-body");

  let clickjackingSpiderRunning = false;

  clickjackingForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (clickjackingSpiderRunning) return;
    const urls = document.getElementById("clickjacking-start-urls").value
      .split('\n').map(u => u.trim()).filter(Boolean);
    const depth = parseInt(document.getElementById("clickjacking-depth").value, 10);
    const mode = document.getElementById("clickjacking-mode").value;
    const threads = parseInt(document.getElementById("clickjacking-threads").value, 10);
    // Clear log and findings
    clickjackingLog.innerHTML = '';
    clickjackingFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    clickjackingStatus.textContent = 'Running';
    clickjackingStatus.className = 'status-running';
    clickjackingProgress.textContent = '0';
    clickjackingFound.textContent = '0';
    clickjackingStartBtn.disabled = true;
    clickjackingStopBtn.disabled = false;
    clickjackingSpiderRunning = true;
    ipcRenderer.send('clickjacking-spider:start', {
      urls, depth, mode, threads
    });
    appendClickjackingLog('Started Clickjacking Spider on ' + urls.join(', '), 'action');
  });

  clickjackingStopBtn.addEventListener("click", () => {
    if (!clickjackingSpiderRunning) return;
    ipcRenderer.send('clickjacking-spider:stop');
    appendClickjackingLog('Stopping Clickjacking Spider...', 'action');
    clickjackingStatus.textContent = 'Stopping...';
    clickjackingStatus.className = 'status-stopping';
    clickjackingStopBtn.disabled = true;
  });

  ipcRenderer.on('clickjacking-spider:log', (event, msg, type = 'info') => {
    appendClickjackingLog(msg, type);
  });
  ipcRenderer.on('clickjacking-spider:progress', (event, progress) => {
    clickjackingProgress.textContent = progress;
  });
  ipcRenderer.on('clickjacking-spider:found', (event, count) => {
    clickjackingFound.textContent = count;
  });
  ipcRenderer.on('clickjacking-spider:status', (event, status) => {
    clickjackingStatus.textContent = status;
    clickjackingStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      clickjackingStartBtn.disabled = false;
      clickjackingStopBtn.disabled = true;
      clickjackingSpiderRunning = false;
    }
  });
  ipcRenderer.on('clickjacking-spider:finding', (event, finding) => {
    addClickjackingFinding(finding);
  });
  ipcRenderer.on('clickjacking-spider:clear', () => {
    clickjackingLog.innerHTML = '';
    clickjackingFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    clickjackingProgress.textContent = '0';
    clickjackingFound.textContent = '0';
  });

  function appendClickjackingLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    clickjackingLog.appendChild(entry);
    clickjackingLog.scrollTop = clickjackingLog.scrollHeight;
  }

  function addClickjackingFinding(finding) {
    if (clickjackingFindingsBody.querySelector('.placeholder')) clickjackingFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.iframeMode || ''}</td>
      <td>${finding.headers || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    clickjackingFindingsBody.appendChild(tr);
  }

  // CORS Spider controls
  const corsForm = document.getElementById("cors-spider-form");
  const corsStartBtn = document.getElementById("cors-start-btn");
  const corsStopBtn = document.getElementById("cors-stop-btn");
  const corsStatus = document.getElementById("cors-status").querySelector("span");
  const corsProgress = document.getElementById("cors-progress").querySelector("span");
  const corsFound = document.getElementById("cors-found").querySelector("span");
  const corsLog = document.getElementById("cors-spider-log");
  const corsFindingsBody = document.getElementById("cors-findings-body");

  let corsSpiderRunning = false;

  corsForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (corsSpiderRunning) return;
    const urls = document.getElementById("cors-start-urls").value
      .split('\n').map(u => u.trim()).filter(Boolean);
    const scanMode = document.getElementById("cors-scan-mode").value;
    const threads = parseInt(document.getElementById("cors-threads").value, 10);
    // Clear log and findings
    corsLog.innerHTML = '';
    corsFindingsBody.innerHTML = '<tr><td colspan="7" class="placeholder">No findings yet.</td></tr>';
    corsStatus.textContent = 'Running';
    corsStatus.className = 'status-running';
    corsProgress.textContent = '0';
    corsFound.textContent = '0';
    corsStartBtn.disabled = true;
    corsStopBtn.disabled = false;
    corsSpiderRunning = true;
    ipcRenderer.send('cors-spider:start', {
      urls, scanMode, threads
    });
    appendCorsLog('Started CORS Spider on ' + urls.join(', '), 'action');
  });

  corsStopBtn.addEventListener("click", () => {
    if (!corsSpiderRunning) return;
    ipcRenderer.send('cors-spider:stop');
    appendCorsLog('Stopping CORS Spider...', 'action');
    corsStatus.textContent = 'Stopping...';
    corsStatus.className = 'status-stopping';
    corsStopBtn.disabled = true;
  });

  ipcRenderer.on('cors-spider:log', (event, msg, type = 'info') => {
    appendCorsLog(msg, type);
  });
  ipcRenderer.on('cors-spider:progress', (event, progress) => {
    corsProgress.textContent = progress;
  });
  ipcRenderer.on('cors-spider:found', (event, count) => {
    corsFound.textContent = count;
  });
  ipcRenderer.on('cors-spider:status', (event, status) => {
    corsStatus.textContent = status;
    corsStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      corsStartBtn.disabled = false;
      corsStopBtn.disabled = true;
      corsSpiderRunning = false;
    }
  });
  ipcRenderer.on('cors-spider:finding', (event, finding) => {
    addCorsFinding(finding);
  });
  ipcRenderer.on('cors-spider:clear', () => {
    corsLog.innerHTML = '';
    corsFindingsBody.innerHTML = '<tr><td colspan="7" class="placeholder">No findings yet.</td></tr>';
    corsProgress.textContent = '0';
    corsFound.textContent = '0';
  });

  function appendCorsLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    corsLog.appendChild(entry);
    corsLog.scrollTop = corsLog.scrollHeight;
  }

  function addCorsFinding(finding) {
    if (corsFindingsBody.querySelector('.placeholder')) corsFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.endpoint || ''}</td>
      <td>${finding.method || ''}</td>
      <td>${finding.origin || ''}</td>
      <td>${finding.corsHeaders || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    corsFindingsBody.appendChild(tr);
  }

  // Subdomain Takeover Spider controls
  const subdomainForm = document.getElementById("subdomain-spider-form");
  const subdomainStartBtn = document.getElementById("subdomain-start-btn");
  const subdomainStopBtn = document.getElementById("subdomain-stop-btn");
  const subdomainStatus = document.getElementById("subdomain-status").querySelector("span");
  const subdomainProgress = document.getElementById("subdomain-progress").querySelector("span");
  const subdomainFound = document.getElementById("subdomain-found").querySelector("span");
  const subdomainLog = document.getElementById("subdomain-spider-log");
  const subdomainFindingsBody = document.getElementById("subdomain-findings-body");

  let subdomainSpiderRunning = false;

  subdomainForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (subdomainSpiderRunning) return;
    const urls = document.getElementById("subdomain-start-urls").value
      .split('\n').map(u => u.trim()).filter(Boolean);
    const scanMode = document.getElementById("subdomain-scan-mode").value;
    // Clear log and findings
    subdomainLog.innerHTML = '';
    subdomainFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    subdomainStatus.textContent = 'Running';
    subdomainStatus.className = 'status-running';
    subdomainProgress.textContent = '0';
    subdomainFound.textContent = '0';
    subdomainStartBtn.disabled = true;
    subdomainStopBtn.disabled = false;
    subdomainSpiderRunning = true;
    ipcRenderer.send('subdomain-spider:start', {
      urls, scanMode
    });
    appendSubdomainLog('Started Subdomain Takeover Spider on ' + urls.join(', '), 'action');
  });

  subdomainStopBtn.addEventListener("click", () => {
    if (!subdomainSpiderRunning) return;
    ipcRenderer.send('subdomain-spider:stop');
    appendSubdomainLog('Stopping Subdomain Takeover Spider...', 'action');
    subdomainStatus.textContent = 'Stopping...';
    subdomainStatus.className = 'status-stopping';
    subdomainStopBtn.disabled = true;
  });

  ipcRenderer.on('subdomain-spider:log', (event, msg, type = 'info') => {
    appendSubdomainLog(msg, type);
  });
  ipcRenderer.on('subdomain-spider:progress', (event, progress) => {
    subdomainProgress.textContent = progress;
  });
  ipcRenderer.on('subdomain-spider:found', (event, count) => {
    subdomainFound.textContent = count;
  });
  ipcRenderer.on('subdomain-spider:status', (event, status) => {
    subdomainStatus.textContent = status;
    subdomainStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      subdomainStartBtn.disabled = false;
      subdomainStopBtn.disabled = true;
      subdomainSpiderRunning = false;
    }
  });
  ipcRenderer.on('subdomain-spider:finding', (event, finding) => {
    addSubdomainFinding(finding);
  });
  ipcRenderer.on('subdomain-spider:clear', () => {
    subdomainLog.innerHTML = '';
    subdomainFindingsBody.innerHTML = '<tr><td colspan="6" class="placeholder">No findings yet.</td></tr>';
    subdomainProgress.textContent = '0';
    subdomainFound.textContent = '0';
  });

  function appendSubdomainLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    subdomainLog.appendChild(entry);
    subdomainLog.scrollTop = subdomainLog.scrollHeight;
  }

  function addSubdomainFinding(finding) {
    if (subdomainFindingsBody.querySelector('.placeholder')) subdomainFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.subdomain || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.reason || ''}</td>
      <td>${finding.dns || ''}</td>
      <td>${finding.service || ''}</td>
      <td>${finding.response || ''}</td>
    `;
    subdomainFindingsBody.appendChild(tr);
  }

  // WordPress Recon Spider controls
  const wordpressreconForm = document.getElementById("wordpressrecon-spider-form");
  const wordpressreconStartBtn = document.getElementById("wordpressrecon-start-btn");
  const wordpressreconStopBtn = document.getElementById("wordpressrecon-stop-btn");
  const wordpressreconStatus = document.getElementById("wordpressrecon-status").querySelector("span");
  const wordpressreconProgress = document.getElementById("wordpressrecon-progress").querySelector("span");
  const wordpressreconFound = document.getElementById("wordpressrecon-found").querySelector("span");
  const wordpressreconLog = document.getElementById("wordpressrecon-spider-log");
  const wordpressreconFindingsBody = document.getElementById("wordpressrecon-findings-body");

  let wordpressreconSpiderRunning = false;

  wordpressreconForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (wordpressreconSpiderRunning) return;
    const urls = document.getElementById("wordpressrecon-start-urls").value
      .split('\n').map(u => u.trim()).filter(Boolean);
    const enumPlugins = document.getElementById("wordpressrecon-enum-plugins").checked;
    const enumThemes = document.getElementById("wordpressrecon-enum-themes").checked;
    const enumUsers = document.getElementById("wordpressrecon-enum-users").checked;
    const deepScan = document.getElementById("wordpressrecon-deep-scan").checked;
    const threads = parseInt(document.getElementById("wordpressrecon-threads").value, 10);
    // Clear log and findings
    wordpressreconLog.innerHTML = '';
    wordpressreconFindingsBody.innerHTML = '<tr><td colspan="5" class="placeholder">No findings yet.</td></tr>';
    wordpressreconStatus.textContent = 'Running';
    wordpressreconStatus.className = 'status-running';
    wordpressreconProgress.textContent = '0';
    wordpressreconFound.textContent = '0';
    wordpressreconStartBtn.disabled = true;
    wordpressreconStopBtn.disabled = false;
    wordpressreconSpiderRunning = true;
    ipcRenderer.send('wordpressrecon-spider:start', {
      urls, enumPlugins, enumThemes, enumUsers, deepScan, threads
    });
    appendWordpressReconLog('Started WordPress Recon Spider on ' + urls.join(', '), 'action');
  });

  wordpressreconStopBtn.addEventListener("click", () => {
    if (!wordpressreconSpiderRunning) return;
    ipcRenderer.send('wordpressrecon-spider:stop');
    appendWordpressReconLog('Stopping WordPress Recon Spider...', 'action');
    wordpressreconStatus.textContent = 'Stopping...';
    wordpressreconStatus.className = 'status-stopping';
    wordpressreconStopBtn.disabled = true;
  });

  ipcRenderer.on('wordpressrecon-spider:log', (event, msg, type = 'info') => {
    appendWordpressReconLog(msg, type);
  });
  ipcRenderer.on('wordpressrecon-spider:progress', (event, progress) => {
    wordpressreconProgress.textContent = progress;
  });
  ipcRenderer.on('wordpressrecon-spider:found', (event, count) => {
    wordpressreconFound.textContent = count;
  });
  ipcRenderer.on('wordpressrecon-spider:status', (event, status) => {
    wordpressreconStatus.textContent = status;
    wordpressreconStatus.className = status === 'Running' ? 'status-running' : (status === 'Idle' ? 'status-idle' : 'status-stopping');
    if (status === 'Idle' || status === 'Stopped') {
      wordpressreconStartBtn.disabled = false;
      wordpressreconStopBtn.disabled = true;
      wordpressreconSpiderRunning = false;
    }
  });
  ipcRenderer.on('wordpressrecon-spider:finding', (event, finding) => {
    addWordpressReconFinding(finding);
  });
  ipcRenderer.on('wordpressrecon-spider:clear', () => {
    wordpressreconLog.innerHTML = '';
    wordpressreconFindingsBody.innerHTML = '<tr><td colspan="5" class="placeholder">No findings yet.</td></tr>';
    wordpressreconProgress.textContent = '0';
    wordpressreconFound.textContent = '0';
  });

  function appendWordpressReconLog(message, type = "info") {
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${type.toUpperCase()}] ${message}`;
    wordpressreconLog.appendChild(entry);
    wordpressreconLog.scrollTop = wordpressreconLog.scrollHeight;
  }

  function addWordpressReconFinding(finding) {
    if (wordpressreconFindingsBody.querySelector('.placeholder')) wordpressreconFindingsBody.innerHTML = '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type || ''}</td>
      <td>${finding.target || ''}</td>
      <td>${finding.detail || ''}</td>
      <td>${finding.status || ''}</td>
      <td>${finding.evidence || ''}</td>
    `;
    wordpressreconFindingsBody.appendChild(tr);
  }
});
