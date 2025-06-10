const { app, BrowserWindow, ipcMain, globalShortcut, session, net, dialog, webContents } = require("electron")
const path = require("path")
const dns = require("dns").promises
const fs = require('fs').promises
const https = require("https")
const dependencyChecker = require("./simple-dependency-checker")
const SimpleHtmlParser = require("./simple-html-parser")
const SimpleWhois = require("./simple-whois")
const { spawn } = require("child_process") // For running PowerShell
const { fork } = require("child_process") // For running child processes
const parse = SimpleHtmlParser.parse
const htmlParser = SimpleHtmlParser
let illusionWindow = null; // Add this line manually at the top level

const burpCADevBypass = true; // Set to true to allow Burp interception without CA install (dev only)
if (burpCADevBypass) {
  app.commandLine.appendSwitch('ignore-certificate-errors');
  console.warn('[SECURITY WARNING] Ignoring certificate errors for proxy interception. This is insecure and should only be used for development/testing with Burp Suite.');
}

let burpProxyEnabled = false; // Track proxy state globally (default: disabled)

app.whenReady().then(async () => {
  // Initialize with no proxy
  await session.defaultSession.setProxy({ mode: 'direct' });
  const webviewSession = session.fromPartition('persist:webviewsession');
  await webviewSession.setProxy({ mode: 'direct' });
  console.log('[Startup] Initialized with proxy disabled');

  setupEnvironmentVariables();
  createWindow();
  console.log("Using built-in alternatives for external dependencies");
});

// Add this function to set up environment variables
function setupEnvironmentVariables() {
  // Set default environment variables if they don't exist
  if (!process.env.APPDATA && process.platform === "win32") {
    process.env.APPDATA = path.join(process.env.USERPROFILE || process.env.HOMEPATH || "", "AppData", "Roaming")
  }
  
  // Set app icon path
  global.appIcon = path.join(__dirname, 'images', 'webslinger.ico')
  
  if (!process.env.HOME) {
    if (process.platform === "win32") {
      process.env.HOME = process.env.USERPROFILE || process.env.HOMEPATH || ""
    } else {
      process.env.HOME = require("os").homedir()
    }
  }

  if (!process.env.USERPROFILE && process.platform === "win32") {
    process.env.USERPROFILE = process.env.HOME
  }

  if (!process.env.LOCALAPPDATA && process.platform === "win32") {
    process.env.LOCALAPPDATA = path.join(process.env.USERPROFILE || process.env.HOMEPATH || "", "AppData", "Local")
  }

  console.log("Environment variables configured:")
  console.log("HOME:", process.env.HOME)
  console.log("APPDATA:", process.env.APPDATA)
  console.log("USERPROFILE:", process.env.USERPROFILE)
  console.log("LOCALAPPDATA:", process.env.LOCALAPPDATA)
}

let mainWindow,
  arsenalWindow,
  proxyWindow = null,
  webReconWindow = null,
  bruteforceWindow = null,
  nmapScannerWindow = null,
  injectionTesterWindow = null,
  spidersWindow = null
const pendingRequests = new Map()
let isInterceptActive = false

// Declare the missing functions
const stopInterception = () => {
  console.log("stopInterception placeholder function")
}
const startInterception = () => {
  console.log("startInterception placeholder function")
}
const captureResponse = (originalId, requestId) => {
  console.log(`captureResponse placeholder function for ${originalId} and ${requestId}`)
}

ipcMain.handle('illusion:set-burp-proxy-enabled', async (event, enabled) => {
  try {
    burpProxyEnabled = !!enabled;
    const proxyConfig = burpProxyEnabled
      ? { proxyRules: 'http=127.0.0.1:8080;https=127.0.0.1:8080' }
      : { mode: 'direct' };

    // Set for default session
    await session.defaultSession.setProxy(proxyConfig);
    // Set for webview session
    const webviewSession = session.fromPartition('persist:webviewsession');
    await webviewSession.setProxy(proxyConfig);

    // Notify renderer(s) of new state
    if (BrowserWindow.getAllWindows) {
      BrowserWindow.getAllWindows().forEach(win => {
        win.webContents.send('illusion:burp-proxy-state', burpProxyEnabled);
        win.webContents.send('illusion:apply-proxy-to-webview', proxyConfig);
      });
    }
    return { success: true };
  } catch (e) {
    console.error('[Burp Proxy Toggle] Failed to set proxy:', e);
    return { success: false, error: e.message };
  }
});

// Add helper functions for config and memory paths
function getUserDataConfigPath() {
  return path.join(app.getPath('userData'), 'config.json');
}
function getUserDataMemoryPath() {
  return path.join(app.getPath('userData'), 'charlotte_memory.json');
}

// API Key Management
async function saveApiKey(key) {
    let success = false;
    try {
        // Save to userData directory ONLY
        const userDataPath = getUserDataConfigPath();
        let userDataConfig = {};
        try {
            const data = await fs.readFile(userDataPath, 'utf8');
            userDataConfig = JSON.parse(data);
        } catch (err) { /* ignore */ }
        userDataConfig.GEMINI_API_KEY = key;
        await fs.writeFile(userDataPath, JSON.stringify(userDataConfig, null, 2));
        success = true;
    } catch (error) {
        console.error('Error saving API key to userData:', error);
    }
    return success;
}

// Modify loadApiKey to check userData first, then fallback to __dirname
async function loadApiKey() {
    try {
        const userDataPath = getUserDataConfigPath();
        try {
            const data = await fs.readFile(userDataPath, 'utf8');
            const config = JSON.parse(data);
            if (config.GEMINI_API_KEY) return config.GEMINI_API_KEY;
        } catch (err) { /* ignore */ }
        // Fallback: read from __dirname (read-only after packaging)
        const localConfigPath = path.join(__dirname, 'config.json');
        try {
            const data = await fs.readFile(localConfigPath, 'utf8');
            const config = JSON.parse(data);
            return config.GEMINI_API_KEY || null;
        } catch (err) {
            return null;
        }
    } catch (error) {
        console.error('Error loading API key:', error);
        return null;
    }
}

// Handle API key IPC events
ipcMain.on('save-api-key', async (event, key) => {
    const success = await saveApiKey(key);
    event.reply('api-key-saved', success);
});

ipcMain.handle('load-api-key', async () => {
    return await loadApiKey();
});

function createWindow() {  
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webviewTag: true,
    },
    backgroundColor: "#0a0a0a",
    icon: path.join(__dirname, "images", "webslinger.ico"),
  });

  mainWindow.loadFile("index.html");

  // --- Download Handling ---
  mainWindow.webContents.session.on('will-download', async (event, item, webContents) => {
    // Prevent Electron's default download behavior
    event.preventDefault();

    // Suggest a filename
    const filename = item.getFilename();
    const { dialog } = require('electron');
    const saveDialog = await dialog.showSaveDialog(mainWindow, {
      title: 'Save File',
      defaultPath: filename,
      buttonLabel: 'Save',
    });

    if (saveDialog.canceled || !saveDialog.filePath) {
      item.cancel();
      return;
    }

    // Pipe the download to the chosen file path
    const fs = require('fs');
    const fileStream = fs.createWriteStream(saveDialog.filePath);

    item.on('updated', (event, state) => {
      if (state === 'interrupted') {
        console.error('Download interrupted');
      } else if (state === 'progressing') {
        // Optionally, send progress to renderer
        // webContents.send('download-progress', { received: item.getReceivedBytes(), total: item.getTotalBytes() });
      }
    });

    item.on('done', (event, state) => {
      if (state === 'completed') {
        // Optionally, notify renderer of completion
        // webContents.send('download-complete', saveDialog.filePath);
      } else {
        console.error(`Download failed: ${state}`);
      }
    });

    // Start the download
    item.pipe(fileStream);
  });

  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('illusion:burp-proxy-state', burpProxyEnabled);
  });

  // Register global shortcut
  globalShortcut.register("CommandOrControl+X", toggleArsenal)
  globalShortcut.register("CommandOrControl+P", toggleProxy)

  mainWindow.on("closed", () => {
    if (arsenalWindow && !arsenalWindow.isDestroyed()) arsenalWindow.close()
    if (proxyWindow && !proxyWindow.isDestroyed()) proxyWindow.close()
    if (webReconWindow && !webReconWindow.isDestroyed()) webReconWindow.close()
    if (bruteforceWindow && !bruteforceWindow.isDestroyed()) bruteforceWindow.close()
    if (nmapScannerWindow && !nmapScannerWindow.isDestroyed()) nmapScannerWindow.close()
    if (injectionTesterWindow && !injectionTesterWindow.isDestroyed()) injectionTesterWindow.close()
    if (spidersWindow && !spidersWindow.isDestroyed()) spidersWindow.close()
  })
}

function toggleArsenal() {
  if (arsenalWindow && !arsenalWindow.isDestroyed()) {
    arsenalWindow.close()
    arsenalWindow = null
  } else {
    createArsenalWindow()
  }
}

function toggleProxy() {
  if (proxyWindow && !proxyWindow.isDestroyed()) {
    proxyWindow.close()
    proxyWindow = null
  } else {
    createProxyWindow()
  }
}

function createArsenalWindow() {
  if (arsenalWindow && !arsenalWindow.isDestroyed()) return

  arsenalWindow = new BrowserWindow({
    width: 800,
    height: 600,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    parent: mainWindow,
  })

  arsenalWindow.loadFile("arsenal.html")
  arsenalWindow.on("closed", () => {
    arsenalWindow = null
    // Don't close proxy window when arsenal is closed
  })
}

function createProxyWindow() {
  if (proxyWindow && !proxyWindow.isDestroyed()) {
    proxyWindow.focus()
    return
  }

  proxyWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    // Make proxy independent (not a child of arsenal)
    parent: mainWindow,
    show: false,
  })

  proxyWindow.loadFile("proxy.html")

  proxyWindow.once("ready-to-show", () => {
    proxyWindow.show()
  })

  proxyWindow.on("closed", () => {
    proxyWindow = null
    // Disable interception when proxy window is closed
    isInterceptActive = false
    stopInterception()
  })
}

function createWebReconWindow() {
  if (webReconWindow && !webReconWindow.isDestroyed()) {
    webReconWindow.focus()
    return
  }

  webReconWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    parent: mainWindow,
    show: false,
  })

  webReconWindow.loadFile("web-recon.html")

  webReconWindow.once("ready-to-show", () => {
    webReconWindow.show()
  })

  webReconWindow.on("closed", () => {
    webReconWindow = null
  })
}

function createBruteforceWindow() {
  if (bruteforceWindow && !bruteforceWindow.isDestroyed()) {
    bruteforceWindow.focus()
    return
  }

  bruteforceWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    parent: mainWindow,
    show: false,
  })

  bruteforceWindow.loadFile("bruteforcer.html")

  bruteforceWindow.once("ready-to-show", () => {
    bruteforceWindow.show()
  })

  bruteforceWindow.on("closed", () => {
    bruteforceWindow = null
  })
}

function createNmapScannerWindow() {
  if (nmapScannerWindow && !nmapScannerWindow.isDestroyed()) {
    nmapScannerWindow.focus()
    return
  }

  nmapScannerWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    parent: mainWindow,
    show: false,
  })

  nmapScannerWindow.loadFile("nmap-scanner.html")

  nmapScannerWindow.once("ready-to-show", () => {
    nmapScannerWindow.show()
  })

  nmapScannerWindow.on("closed", () => {
    nmapScannerWindow = null
  })
}

function createInjectionTesterWindow() {
  if (injectionTesterWindow && !injectionTesterWindow.isDestroyed()) {
    injectionTesterWindow.focus()
    return
  }

  injectionTesterWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    parent: mainWindow,
    show: false,
  })

  injectionTesterWindow.loadFile("injection-tester.html")

  injectionTesterWindow.once("ready-to-show", () => {
    injectionTesterWindow.show()
  })

  injectionTesterWindow.on("closed", () => {
    injectionTesterWindow = null
  })
}

function createSpidersWindow() {
  if (spidersWindow && !spidersWindow.isDestroyed()) {
    spidersWindow.focus()
    return
  }
  spidersWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    transparent: true,
    frame: false,
    resizable: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    vibrancy: "under-window",
    visualEffectState: "active",
    titleBarStyle: "hidden",
    parent: mainWindow,
    show: false,
  })
  spidersWindow.loadFile("spider.html")
  spidersWindow.once("ready-to-show", () => {
    spidersWindow.show()
  })
  spidersWindow.on("closed", () => {
    spidersWindow = null
  })
}

// Helper function to extract and sanitize request details for IPC
function sanitizeRequestDetails(details) {
  try {
    // Create a new object with all the properties we need
    const sanitized = {
      id: details.id,
      url: details.url,
      method: details.method,
      timestamp: Date.now(),
      resourceType: details.resourceType || "unknown",
      referrer: details.referrer || "",
      requestHeaders: {},
      postData: null,
    }

    // Extract the hostname from the URL
    try {
      const urlObj = new URL(details.url)
      sanitized.hostname = urlObj.hostname
    } catch (e) {
      sanitized.hostname = ""
    }

    // Safely copy request headers
    if (details.requestHeaders) {
      Object.keys(details.requestHeaders).forEach((key) => {
        sanitized.requestHeaders[key] = details.requestHeaders[key]
      })
    }

    // Replace the existing uploadData handling with this improved version
    if (details.uploadData && details.uploadData.length > 0) {
      sanitized.uploadData = []
      let postBody = "" // Aggregate all data chunks

      details.uploadData.forEach((data) => {
        if (data.bytes) {
          try {
            // Convert Buffer to string
            const str = Buffer.from(data.bytes).toString("utf8")
            postBody += str
          } catch (e) {
            postBody += "[Binary data]"
          }
        }
      })

      sanitized.postData = postBody
    }

    return sanitized
  } catch (error) {
    console.error("Error sanitizing request details:", error)
    return {
      id: details.id,
      url: details.url,
      method: details.method,
      timestamp: Date.now(),
      error: "Failed to sanitize request details",
    }
  }
}

// Helper function to sanitize response details for IPC
function sanitizeResponseDetails(details) {
  try {
    const sanitized = {
      url: details.url,
      statusCode: details.statusCode,
      statusLine: details.statusLine || `HTTP/1.1 ${details.statusCode}`,
      responseHeaders: {},
      timestamp: Date.now(),
    }

    // Safely copy response headers
    if (details.responseHeaders) {
      Object.keys(details.responseHeaders).forEach((key) => {
        sanitized.responseHeaders[key] = details.responseHeaders[key]
      })
    }

    return sanitized
  } catch (error) {
    console.error("Error sanitizing response details:", error)
    return {
      url: details.url,
      statusCode: details.statusCode,
      error: "Failed to sanitize response details",
    }
  }
}

// Updated function to capture response body
async function captureResponseBody(requestId) {
  try {
    const request = pendingRequests.get(requestId)
    if (!request) return

    const originalUrl = request.details.url

    // Use Electron's net module to fetch the response
    const netRequest = net.request({
      method: request.details.method,
      url: originalUrl,
    })

    // Copy headers from original request
    if (request.details.requestHeaders) {
      Object.entries(request.details.requestHeaders).forEach(([key, value]) => {
        if (key.toLowerCase() !== "host") {
          // Skip host header as it's set automatically
          netRequest.setHeader(key, value)
        }
      })
    }

    // Add body for POST/PUT requests
    if (request.details.postData && (request.details.method === "POST" || request.details.method === "PUT")) {
      netRequest.write(request.details.postData)
    }

    // Get response
    const response = await new Promise((resolve, reject) => {
      const chunks = []

      netRequest.on("response", (response) => {
        response.on("data", (chunk) => {
          chunks.push(chunk)
        })

        response.on("end", () => {
          try {
            const body = Buffer.concat(chunks).toString()
            resolve({
              body: body,
              statusCode: response.statusCode,
            })
          } catch (error) {
            resolve({
              body: "[Failed to convert response body to string]",
              statusCode: response.statusCode,
            })
          }
        })
      })

      netRequest.on("error", (error) => {
        console.error("Error capturing response body:", error)
        reject(error)
      })

      netRequest.end()
    })

    if (proxyWindow && !proxyWindow.isDestroyed()) {
      proxyWindow.webContents.send("response-body", requestId, response)
    }
  } catch (error) {
    console.error("Error capturing response body:", error)
  }
}


// --- 5. Provide Active Credentials (for Webview Auth Handler) ---
ipcMain.handle('proxy:get-auth-credentials', (event) => {
  // This function simply returns the credentials stored in main.js
  console.log('[ProxyManager Main] Webview requested credentials. Providing:', activeProxyCredentials ? 'Stored Credentials' : 'None');
  return activeProxyCredentials; // Return the stored object or null
});
console.log("[ProxyManager Main] Registered 'proxy:get-auth-credentials' handler.");

  // Add handlers for window control messages
  ipcMain.on("minimize-window", (event) => {
    const sender = BrowserWindow.fromWebContents(event.sender)
    if (sender) {
      sender.minimize()
      console.log("Window minimized")
    }
  })

  ipcMain.on("close-window", (event) => {
    const sender = BrowserWindow.fromWebContents(event.sender)
    if (sender) {
      sender.close()
      console.log("Window closed")
    }
  })

  ipcMain.on('toggle-maximize-window', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    if (win.isMaximized()) {
      win.unmaximize();
    } else {
      win.maximize();
    }
  });

  // Toggle proxy interception
  ipcMain.on("toggle-interception", (event, enabled) => {
    isInterceptActive = enabled
    console.log(`Interception ${enabled ? "enabled" : "disabled"}`)

    if (enabled) {
      startInterception()
    } else {
      stopInterception()
    }

    // Notify all windows about the interception state
    if (mainWindow) mainWindow.webContents.send("interception-state-changed", enabled)
    if (proxyWindow) proxyWindow.webContents.send("interception-state-changed", enabled)
  })

  // Handle proxy toggle from arsenal
  ipcMain.handle("toggle-proxy", (event, enabled) => {
    if (enabled) {
      createProxyWindow()
    } else {
      if (proxyWindow && !proxyWindow.isDestroyed()) {
        proxyWindow.close()
      }
    }
    return true
  })

  // Handle request actions (forward, drop, edit)
  ipcMain.on("request-action", (event, requestId, action, modifiedDetails) => {
    const request = pendingRequests.get(requestId)
    if (!request) {
      console.log(`Request ${requestId} not found`)
      return
    }

    console.log(`Action ${action} for request ${requestId}`)

    if (action === "forward") {
      // Forward the request as is
      request.callback({ cancel: false })

      // Set up response capture
      captureResponse(request.details.id, requestId)
    } else if (action === "drop") {
      // Cancel the request
      request.callback({ cancel: true })
    } else if (action === "edit" && modifiedDetails) {
      const options = {
        cancel: false,
        requestHeaders: modifiedDetails.headers,
        url: modifiedDetails.url || request.details.url, // Use modified URL
        method: modifiedDetails.method || request.details.method, // Use modified method
      }

      // Add uploadData if body is modified
      if (modifiedDetails.body) {
        options.uploadData = [
          {
            bytes: Buffer.from(modifiedDetails.body, "utf8"),
          },
        ]
      }

      request.callback(options)

      // Set up response capture
      captureResponse(request.details.id, requestId)
    }

    pendingRequests.delete(requestId)
  })

  ipcMain.on("open-proxy", () => {
    createProxyWindow()
  })

  ipcMain.on("open-web-recon", () => {
    createWebReconWindow()
  })

  ipcMain.on("open-bruteforcer", () => {
    createBruteforceWindow()
  })

  ipcMain.on("open-nmap-scanner", () => {
    createNmapScannerWindow()
  })

  ipcMain.on("open-injection-tester", () => {
    createInjectionTesterWindow()
  })

  ipcMain.on("open-spiders", () => {
    createSpidersWindow()
  })

  // Enhanced website analysis
  ipcMain.handle("analyze-website", async (event, url, options) => {
    try {
      if (!htmlParser) {
        return {
          url,
          error:
            "HTML parser module not installed. Please run 'npm install node-html-parser' to enable full functionality.",
        }
      }
      console.log(`Analyzing website: ${url} with options:`, options)

      // Make HTTP request to get the website content with proper redirect handling
      const response = await fetchWithRedirects(url, options.followRedirects)

      const html = response.body
      const headers = response.headers
      const finalUrl = response.url

      // Parse HTML
      const root = parse(html)

      // Extract all resources
      const scripts = extractScripts(root, finalUrl)
      const cssFiles = extractCssFiles(root, finalUrl)
      const images = extractImages(root, finalUrl)
      const forms = extractForms(root)
      const links = extractLinks(root, finalUrl)

      // Extract cookies
      const cookies = extractCookies(headers)

      // Basic tech detection patterns
      const technologies = detectTechnologies(html, headers, finalUrl, scripts)

      // Generate HTML structure summary
      const htmlStructure = generateHtmlStructure(root)

      // Get SSL information if HTTPS
      const sslInfo = finalUrl.startsWith("https://") ? await getSSLInfo(finalUrl) : null

      // Analyze content for potential vulnerabilities
      const vulnerabilities = analyzeVulnerabilities(html, headers, finalUrl)

      // Get IP information
      const ipInfo = await getIpInfo(finalUrl)

      return {
        url: finalUrl,
        status: response.statusCode,
        headers,
        technologies,
        title: extractTitle(root),
        metaTags: extractMetaTags(root),
        links,
        scripts,
        cssFiles,
        images,
        forms,
        cookies,
        htmlStructure,
        sslInfo,
        vulnerabilities,
        ipInfo,
      }
    } catch (error) {
      console.error("Error analyzing website:", error)
      return {
        url,
        error: error.message,
      }
    }
  })

  // Replace the get-domain-info handler with:
  ipcMain.handle("get-domain-info", async (event, domain) => {
    try {
      console.log(`Getting domain info for: ${domain}`)

      // Use our simple WHOIS implementation
      const whoisData = await SimpleWhois.lookup(domain)

      // Get DNS information
      const dnsRecords = await getDomainDnsInfo(domain)

      return {
        registrar: whoisData.registrar || "Information not available",
        creationDate: whoisData.creationDate || estimateDomainAge(domain) || "Unknown",
        expirationDate: whoisData.expirationDate || "Information not available",
        updatedDate: whoisData.updatedDate || "Information not available",
        nameServers: whoisData.nameServers || dnsRecords.ns || [],
        status: whoisData.status || ["Information not available"],
        whois: whoisData.text || "WHOIS information not available.",
        note: whoisData.error ? "Using simplified WHOIS implementation. Results may be limited." : "",
      }
    } catch (error) {
      console.error("Error getting domain info:", error)
      return {
        error: error.message,
        note: "Using simplified WHOIS implementation. Results may be limited.",
      }
    }
  })

  // Add these handlers in the app.whenReady().then() section
  ipcMain.on("open-internal-browser", (event, url) => {
    // Send the URL to the main window to open in the webview
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("open-url-in-webview", url)
    }
  })

  // Add these handlers for deep analysis
  ipcMain.handle("analyze-js-files", async (event, scriptUrls) => {
    try {
      const libraries = []
      const issues = []

      // Analyze each script
      for (const url of scriptUrls) {
        try {
          const response = await fetchWithRedirects(url, true)
          const jsContent = response.body

          // Check for libraries
          const libraryPatterns = [
            { pattern: /jquery[.-]([0-9.]+)/i, name: "jQuery" },
            { pattern: /bootstrap[.-]([0-9.]+)/i, name: "Bootstrap" },
            { pattern: /react[.-]([0-9.]+)/i, name: "React" },
            { pattern: /angular[.-]([0-9.]+)/i, name: "Angular" },
            { pattern: /vue[.-]([0-9.]+)/i, name: "Vue.js" },
            { pattern: /lodash[.-]([0-9.]+)/i, name: "Lodash" },
            { pattern: /moment[.-]([0-9.]+)/i, name: "Moment.js" },
            { pattern: /axios[.-]([0-9.]+)/i, name: "Axios" },
            { pattern: /three[.-]([0-9.]+)/i, name: "Three.js" },
            { pattern: /d3[.-]([0-9.]+)/i, name: "D3.js" },
          ]

          for (const lib of libraryPatterns) {
            const match = jsContent.match(lib.pattern)
            if (match) {
              libraries.push({
                name: lib.name,
                version: match[1] || "Unknown",
                url: url,
              })
            }
          }

          // Check for potential issues
          const issuePatterns = [
            { pattern: /eval\s*\(/i, description: "Use of eval() detected", severity: "high" },
            { pattern: /document\.write\s*\(/i, description: "Use of document.write() detected", severity: "medium" },
            { pattern: /innerHTML\s*=/i, description: "Use of innerHTML detected", severity: "medium" },
            { pattern: /localStorage\s*\./i, description: "Use of localStorage detected", severity: "low" },
            { pattern: /sessionStorage\s*\./i, description: "Use of sessionStorage detected", severity: "low" },
            {
              pattern: /password.*=.*['"][^'"]*['"]|['"][^'"]*['"].*=.*password/i,
              description: "Hardcoded password detected",
              severity: "high",
            },
            {
              pattern: /api[_-]?key.*=.*['"][^'"]*['"]|['"][^'"]*['"].*=.*api[_-]?key/i,
              description: "Hardcoded API key detected",
              severity: "high",
            },
          ]

          for (const issue of issuePatterns) {
            if (issue.pattern.test(jsContent)) {
              issues.push({
                description: issue.description,
                severity: issue.severity,
                url: url,
              })
            }
          }
        } catch (error) {
          console.error(`Error analyzing script ${url}:`, error)
        }
      }

      return { libraries, issues }
    } catch (error) {
      console.error("Error analyzing JS files:", error)
      return { libraries: [], issues: [] }
    }
  })

  ipcMain.handle("analyze-subdomains", async (event, domain) => {
    try {
      // Common subdomains to check
      const commonSubdomains = [
        "www",
        "mail",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "ns2",
        "dns",
        "dns1",
        "dns2",
        "mx",
        "mx1",
        "mx2",
        "ftp",
        "sftp",
        "ssh",
        "admin",
        "blog",
        "dev",
        "test",
        "staging",
        "api",
        "stage",
        "app",
        "apps",
        "mobile",
        "beta",
        "gateway",
        "vpn",
        "secure",
        "shop",
        "store",
        "payment",
        "cdn",
        "media",
        "img",
        "images",
        "video",
        "videos",
        "static",
        "assets",
        "files",
        "portal",
        "intranet",
        "internal",
        "corp",
        "support",
        "help",
        "kb",
        "faq",
        "docs",
        "wiki",
        "status",
        "monitor",
        "stats",
        "analytics",
        "ads",
        "marketing",
        "crm",
        "hr",
        "jobs",
        "careers",
        "cloud",
      ]

      const subdomains = []

      // Check each subdomain
      for (const sub of commonSubdomains) {
        const subdomain = `${sub}.${domain}`
        try {
          const addresses = await dns.resolve4(subdomain)
          if (addresses && addresses.length > 0) {
            subdomains.push({
              name: subdomain,
              ip: addresses[0],
            })
          }
        } catch (error) {
          // Ignore errors - subdomain doesn't exist
        }
      }

      return { subdomains }
    } catch (error) {
      console.error("Error analyzing subdomains:", error)
      return { subdomains: [] }
    }
  })

  ipcMain.handle("analyze-security", async (event, url, headers) => {
    try {
      // Calculate security score
      let score = 0
      const maxScore = 100
      const criticalIssues = []
      const recommendations = []

      // Check HTTPS
      if (url.startsWith("https://")) {
        score += 20
      } else {
        criticalIssues.push("Site is not using HTTPS")
        recommendations.push("Enable HTTPS to encrypt data in transit")
      }

      // Check security headers
      const securityHeaders = [
        { name: "Content-Security-Policy", header: "content-security-policy", weight: 15 },
        { name: "X-XSS-Protection", header: "x-xss-protection", weight: 10 },
        { name: "X-Frame-Options", header: "x-frame-options", weight: 10 },
        { name: "X-Content-Type-Options", header: "x-content-type-options", weight: 10 },
        { name: "Strict-Transport-Security", header: "strict-transport-security", weight: 15 },
        { name: "Referrer-Policy", header: "referrer-policy", weight: 10 },
        { name: "Permissions-Policy", header: "permissions-policy", weight: 5 },
        { name: "Feature-Policy", header: "feature-policy", weight: 5 },
      ]

      for (const header of securityHeaders) {
        if (headers && headers[header.header]) {
          score += header.weight
        } else {
          if (header.weight >= 15) {
            criticalIssues.push(`Missing ${header.name} header`)
          }
          recommendations.push(`Add ${header.name} header to improve security`)
        }
      }

      // Check for cookies
      if (headers && headers["set-cookie"]) {
        const cookieHeaders = Array.isArray(headers["set-cookie"]) ? headers["set-cookie"] : [headers["set-cookie"]]

        for (const cookie of cookieHeaders) {
          if (!cookie.toLowerCase().includes("secure")) {
            criticalIssues.push("Cookies without Secure flag detected")
            recommendations.push("Add Secure flag to all cookies")
            break
          }
        }

        for (const cookie of cookieHeaders) {
          if (!cookie.toLowerCase().includes("httponly")) {
            recommendations.push("Add HttpOnly flag to cookies to prevent JavaScript access")
            break
          }
        }
      }

      // Normalize score
      score = Math.min(Math.max(score, 0), maxScore)

      return {
        score,
        criticalIssues,
        recommendations,
      }
    } catch (error) {
      console.error("Error analyzing security:", error)
      return {
        score: 0,
        criticalIssues: ["Error analyzing security"],
        recommendations: [],
      }
    }
  })

  ipcMain.handle("analyze-performance", async (event, url) => {
    try {
      const startTime = Date.now()
      const response = await fetchWithRedirects(url, true)
      const loadTime = Date.now() - startTime

      // Calculate page size
      const pageSize = response.body.length
      let pageSizeFormatted

      if (pageSize < 1024) {
        pageSizeFormatted = `${pageSize} B`
      } else if (pageSize < 1024 * 1024) {
        pageSizeFormatted = `${(pageSize / 1024).toFixed(2)} KB`
      } else {
        pageSizeFormatted = `${(pageSize / (1024 * 1024)).toFixed(2)} MB`
      }

      // Check for performance optimizations
      const optimizations = []

      // Check for minification
      if (response.body.includes("\n  ") || response.body.includes("    ")) {
        optimizations.push("HTML is not minified")
      }

      // Check for image optimization
      if (response.body.includes(".jpg") || response.body.includes(".png") || response.body.includes(".gif")) {
        optimizations.push("Consider using WebP or optimized image formats")
      }

      // Check for caching headers
      if (!response.headers["cache-control"] && !response.headers["expires"]) {
        optimizations.push("No caching headers detected")
      }

      // Check for compression
      if (!response.headers["content-encoding"]) {
        optimizations.push("Content compression not enabled")
      }

      // Check for render-blocking resources
      const renderBlockingCount = (response.body.match(/<script[^>]*src=/g) || []).length
      if (renderBlockingCount > 5) {
        optimizations.push(`${renderBlockingCount} render-blocking scripts detected`)
      }

      return {
        loadTime,
        pageSize: pageSizeFormatted,
        optimizations,
      }
    } catch (error) {
      console.error("Error analyzing performance:", error)
      return {
        loadTime: 0,
        pageSize: "Unknown",
        optimizations: ["Error analyzing performance"],
      }
    }
  })

// Function to get domain DNS information
async function getDomainDnsInfo(domain) {
  try {
    const records = {}

    try {
      records.a = await dns.resolve4(domain)
    } catch (e) {
      records.a = []
    }

    try {
      records.aaaa = await dns.resolve6(domain)
    } catch (e) {
      records.aaaa = []
    }

    try {
      records.mx = await dns.resolveMx(domain)
    } catch (e) {
      records.mx = []
    }

    try {
      records.ns = await dns.resolveNs(domain)
    } catch (e) {
      records.ns = []
    }

    try {
      records.txt = await dns.resolveTxt(domain)
    } catch (e) {
      records.txt = []
    }

    return records
  } catch (error) {
    console.error("Error getting DNS records:", error)
    return { error: error.message }
  }
}

// Function to estimate domain age based on common patterns
// This is a very rough estimate and not a replacement for actual WHOIS data
function estimateDomainAge(domain) {
  // Common TLDs and their approximate introduction dates
  const tldDates = {
    com: 1985,
    net: 1985,
    org: 1985,
    edu: 1985,
    gov: 1985,
    mil: 1985,
    int: 1988,
    info: 2001,
    biz: 2001,
    name: 2001,
    pro: 2002,
    aero: 2002,
    coop: 2002,
    museum: 2002,
    travel: 2005,
    jobs: 2005,
    mobi: 2005,
    cat: 2005,
    tel: 2007,
    asia: 2007,
    xxx: 2011,
    app: 2015,
    dev: 2015,
  }

  // Extract TLD
  const tld = domain.split(".").pop().toLowerCase()

  if (tldDates[tld]) {
    const currentYear = new Date().getFullYear()
    const maxAge = currentYear - tldDates[tld]

    // Return a range to indicate uncertainty
    if (maxAge <= 5) {
      return "less than 5 years"
    } else if (maxAge <= 10) {
      return "5-10 years"
    } else if (maxAge <= 20) {
      return "10-20 years"
    } else {
      return "more than 20 years"
    }
  }

  return null
}

// Function to fetch with redirect handling
async function fetchWithRedirects(url, followRedirects = true, maxRedirects = 5) {
  let currentUrl = url
  let redirectCount = 0
  let response = null

  while (redirectCount < maxRedirects) {
    response = await new Promise((resolve, reject) => {
      const isHttps = currentUrl.startsWith("https://")
      const urlObj = new URL(currentUrl)

      const options = {
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: "GET",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          Connection: "keep-alive",
          "Upgrade-Insecure-Requests": "1",
        },
      }

      const req = (isHttps ? https : http).request(options, (res) => {
        const chunks = []

        res.on("data", (chunk) => {
          chunks.push(chunk)
        })

        res.on("end", () => {
          const body = Buffer.concat(chunks).toString()
          const headers = {}

          // Convert headers to object
          for (const [key, value] of Object.entries(res.headers)) {
            headers[key.toLowerCase()] = value
          }

          resolve({
            statusCode: res.statusCode,
            headers,
            body,
            url: currentUrl,
          })
        })
      })

      req.on("error", (error) => {
        reject(error)
      })

      req.end()
    })

    // Check if it's a redirect
    if (followRedirects && [301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
      redirectCount++

      // Handle relative URLs
      if (response.headers.location.startsWith("/")) {
        const urlObj = new URL(currentUrl)
        currentUrl = `${urlObj.protocol}//${urlObj.host}${response.headers.location}`
      } else {
        currentUrl = response.headers.location
      }

      console.log(`Following redirect (${redirectCount}/${maxRedirects}) to: ${currentUrl}`)
    } else {
      break
    }
  }

  return response
}

// Function to extract scripts
function extractScripts(root, baseUrl) {
  const scripts = []
  const scriptTags = root.querySelectorAll("script[src]")

  scriptTags.forEach((script) => {
    let src = script.getAttribute("src")

    // Handle relative URLs
    if (src.startsWith("/")) {
      const urlObj = new URL(baseUrl)
      src = `${urlObj.protocol}//${urlObj.host}${src}`
    } else if (!src.startsWith("http")) {
      const urlObj = new URL(baseUrl)
      src = `${urlObj.protocol}//${urlObj.host}/${src}`
    }

    scripts.push(src)
  })

  return scripts
}

// Function to extract CSS files
function extractCssFiles(root, baseUrl) {
  const cssFiles = []
  const linkTags = root.querySelectorAll('link[rel="stylesheet"]')

  linkTags.forEach((link) => {
    let href = link.getAttribute("href")

    // Handle relative URLs
    if (href.startsWith("/")) {
      const urlObj = new URL(baseUrl)
      href = `${urlObj.protocol}//${urlObj.host}${href}`
    } else if (!href.startsWith("http")) {
      const urlObj = new URL(baseUrl)
      href = `${urlObj.protocol}//${urlObj.host}/${href}`
    }

    cssFiles.push(href)
  })

  return cssFiles
}

// Function to extract images
function extractImages(root, baseUrl) {
  const images = []
  const imgTags = root.querySelectorAll("img[src]")

  imgTags.forEach((img) => {
    let src = img.getAttribute("src")

    // Skip data URLs
    if (src.startsWith("data:")) return

    // Handle relative URLs
    if (src.startsWith("/")) {
      const urlObj = new URL(baseUrl)
      src = `${urlObj.protocol}//${urlObj.host}${src}`
    } else if (!src.startsWith("http")) {
      const urlObj = new URL(baseUrl)
      src = `${urlObj.protocol}//${urlObj.host}/${src}`
    }

    images.push(src)
  })

  return images
}

// Function to extract forms
function extractForms(root) {
  const forms = []
  const formTags = root.querySelectorAll("form")

  formTags.forEach((form) => {
    const action = form.getAttribute("action") || ""
    const method = form.getAttribute("method") || "GET"
    const inputs = []

    form.querySelectorAll("input").forEach((input) => {
      const type = input.getAttribute("type") || "text"
      const name = input.getAttribute("name") || ""

      inputs.push({ type, name })
    })

    forms.push({
      action,
      method,
      inputs,
    })
  })

  return forms
}

// Function to extract links
function extractLinks(root, baseUrl) {
  const links = []
  const linkTags = root.querySelectorAll("a[href]")

  linkTags.forEach((link) => {
    let href = link.getAttribute("href")

    // Skip anchors and javascript links
    if (href.startsWith("#") || href.startsWith("javascript:")) return

    // Handle relative URLs
    if (href.startsWith("/")) {
      const urlObj = new URL(baseUrl)
      href = `${urlObj.protocol}//${urlObj.host}${href}`
    } else if (!href.startsWith("http")) {
      const urlObj = new URL(baseUrl)
      href = `${urlObj.protocol}//${urlObj.host}/${href}`
    }

    links.push(href)
  })

  return [...new Set(links)].slice(0, 50) // Limit to 50 unique links
}

// Function to extract cookies
function extractCookies(headers) {
  const cookies = []

  if (headers["set-cookie"]) {
    const cookieHeaders = Array.isArray(headers["set-cookie"]) ? headers["set-cookie"] : [headers["set-cookie"]]

    cookieHeaders.forEach((cookieStr) => {
      const parts = cookieStr.split(";")
      const nameValue = parts[0].split("=")

      const cookie = {
        name: nameValue[0].trim(),
        value: nameValue[1] ? nameValue[1].trim() : "",
        secure: cookieStr.toLowerCase().includes("secure"),
        httpOnly: cookieStr.toLowerCase().includes("httponly"),
        sameSite: "",
      }

      // Check for SameSite
      const sameSitePart = parts.find((part) => part.trim().toLowerCase().startsWith("samesite="))
      if (sameSitePart) {
        cookie.sameSite = sameSitePart.split("=")[1].trim()
      }

      cookies.push(cookie)
    })
  }

  return cookies
}

// Function to detect technologies
function detectTechnologies(html, headers, url, scripts) {
  const technologies = []

  // Server detection
  if (headers["server"]) {
    technologies.push({
      name: "Server",
      value: headers["server"],
    })
  }

  // Framework detection
  if (headers["x-powered-by"]) {
    technologies.push({
      name: "Powered By",
      value: headers["x-powered-by"],
    })
  }

  // CMS detection - more comprehensive
  if (html.includes("wp-content") || html.includes("wp-includes")) {
    technologies.push({
      name: "CMS",
      value: "WordPress",
    })

    // Try to detect WordPress version
    const wpVersionMatch = html.match(/meta\s+name="generator"\s+content="WordPress\s+([0-9.]+)/i)
    if (wpVersionMatch) {
      technologies.push({
        name: "WordPress Version",
        value: wpVersionMatch[1],
      })
    }
  } else if (html.includes("Drupal.settings")) {
    technologies.push({
      name: "CMS",
      value: "Drupal",
    })
  } else if (html.includes("Joomla!")) {
    technologies.push({
      name: "CMS",
      value: "Joomla",
    })
  } else if (html.includes("Magento")) {
    technologies.push({
      name: "CMS",
      value: "Magento",
    })
  } else if (html.includes("Shopify")) {
    technologies.push({
      name: "CMS",
      value: "Shopify",
    })
  } else if (html.includes("Wix")) {
    technologies.push({
      name: "CMS",
      value: "Wix",
    })
  } else if (html.includes("Squarespace")) {
    technologies.push({
      name: "CMS",
      value: "Squarespace",
    })
  }

  // JavaScript frameworks - more comprehensive
  if (html.includes("react") || html.includes("React") || scripts.some((s) => s.includes("react"))) {
    technologies.push({
      name: "Frontend",
      value: "React",
    })
  } else if (html.includes("angular") || html.includes("Angular") || scripts.some((s) => s.includes("angular"))) {
    technologies.push({
      name: "Frontend",
      value: "Angular",
    })
  } else if (html.includes("vue") || html.includes("Vue") || scripts.some((s) => s.includes("vue"))) {
    technologies.push({
      name: "Frontend",
      value: "Vue.js",
    })
  } else if (html.includes("svelte") || scripts.some((s) => s.includes("svelte"))) {
    technologies.push({
      name: "Frontend",
      value: "Svelte",
    })
  } else if (html.includes("next-page") || html.includes("__NEXT_DATA__")) {
    technologies.push({
      name: "Frontend",
      value: "Next.js",
    })
  } else if (html.includes("nuxt") || html.includes("__NUXT__")) {
    technologies.push({
      name: "Frontend",
      value: "Nuxt.js",
    })
  }

  // UI frameworks
  if (html.includes("bootstrap") || scripts.some((s) => s.includes("bootstrap"))) {
    technologies.push({
      name: "UI",
      value: "Bootstrap",
    })
  } else if (html.includes("tailwind")) {
    technologies.push({
      name: "UI",
      value: "Tailwind CSS",
    })
  } else if (html.includes("material-ui") || html.includes("MuiButton")) {
    technologies.push({
      name: "UI",
      value: "Material UI",
    })
  } else if (html.includes("ant-") || html.includes("antd")) {
    technologies.push({
      name: "UI",
      value: "Ant Design",
    })
  }

  // Analytics
  if (
    html.includes("google-analytics") ||
    html.includes("GoogleAnalytics") ||
    scripts.some((s) => s.includes("google-analytics"))
  ) {
    technologies.push({
      name: "Analytics",
      value: "Google Analytics",
    })
  } else if (html.includes("gtag") || scripts.some((s) => s.includes("gtag"))) {
    technologies.push({
      name: "Analytics",
      value: "Google Tag Manager",
    })
  } else if (html.includes("hotjar") || scripts.some((s) => s.includes("hotjar"))) {
    technologies.push({
      name: "Analytics",
      value: "Hotjar",
    })
  } else if (html.includes("matomo") || scripts.some((s) => s.includes("matomo"))) {
    technologies.push({
      name: "Analytics",
      value: "Matomo",
    })
  }

  // CDN
  if (html.includes("cloudflare") || headers["cf-ray"] || scripts.some((s) => s.includes("cloudflare"))) {
    technologies.push({
      name: "CDN",
      value: "Cloudflare",
    })
  } else if (html.includes("cloudfront") || scripts.some((s) => s.includes("cloudfront"))) {
    technologies.push({
      name: "CDN",
      value: "AWS CloudFront",
    })
  } else if (html.includes("fastly") || headers["x-served-by"]?.includes("cache-") || headers["x-cache"]) {
    technologies.push({
      name: "CDN",
      value: "Fastly",
    })
  } else if (html.includes("akamai") || headers["x-akamai"]) {
    technologies.push({
      name: "CDN",
      value: "Akamai",
    })
  }

  // E-commerce
  if (html.includes("shopify") || url.includes("shopify")) {
    technologies.push({
      name: "E-commerce",
      value: "Shopify",
    })
  } else if (html.includes("woocommerce")) {
    technologies.push({
      name: "E-commerce",
      value: "WooCommerce",
    })
  } else if (html.includes("magento")) {
    technologies.push({
      name: "E-commerce",
      value: "Magento",
    })
  } else if (html.includes("prestashop")) {
    technologies.push({
      name: "E-commerce",
      value: "PrestaShop",
    })
  }

  // Programming languages
  if (headers["x-powered-by"]?.includes("PHP")) {
    technologies.push({
      name: "Backend",
      value: "PHP",
    })
  } else if (headers["x-powered-by"]?.includes("ASP.NET")) {
    technologies.push({
      name: "Backend",
      value: "ASP.NET",
    })
  } else if (headers["x-powered-by"]?.includes("Express")) {
    technologies.push({
      name: "Backend",
      value: "Node.js (Express)",
    })
  } else if (html.includes("__NEXT_DATA__")) {
    technologies.push({
      name: "Backend",
      value: "Node.js (Next.js)",
    })
  } else if (html.includes("rails")) {
    technologies.push({
      name: "Backend",
      value: "Ruby on Rails",
    })
  } else if (html.includes("django")) {
    technologies.push({
      name: "Backend",
      value: "Django (Python)",
    })
  } else if (html.includes("flask")) {
    technologies.push({
      name: "Backend",
      value: "Flask (Python)",
    })
  }

  return technologies
}

// Function to extract title
function extractTitle(root) {
  const titleTag = root.querySelector("title")
  return titleTag ? titleTag.text.trim() : "No title found"
}

// Function to extract meta tags
function extractMetaTags(root) {
  const metaTags = []
  const metaElements = root.querySelectorAll("meta")

  metaElements.forEach((meta) => {
    const name = meta.getAttribute("name") || meta.getAttribute("property") || ""
    const content = meta.getAttribute("content") || ""

    if (name && content) {
      metaTags.push({
        name,
        content,
      })
    }
  })

  return metaTags
}

// Function to generate HTML structure
function generateHtmlStructure(root) {
  // Simplified structure generation
  const structure = []

  // Get main sections
  const header = root.querySelector("header") || root.querySelector(".header")
  const nav = root.querySelector("nav") || root.querySelector(".nav") || root.querySelector(".navigation")
  const main = root.querySelector("main") || root.querySelector(".main") || root.querySelector("#main")
  const footer = root.querySelector("footer") || root.querySelector(".footer")

  if (header) {
    structure.push('<div class="tree-item">Header</div>')
  }

  if (nav) {
    structure.push('<div class="tree-item">Navigation</div>')
  }

  if (main) {
    structure.push('<div class="tree-item">Main Content</div>')

    // Try to identify sections within main
    const sections = main.querySelectorAll("section") || main.querySelectorAll(".section")
    if (sections.length > 0) {
      sections.forEach((section, index) => {
        structure.push(`<div class="tree-item tree-item-child">Section ${index + 1}</div>`)
      })
    }
  }

  if (footer) {
    structure.push('<div class="tree-item">Footer</div>')
  }

  return structure.join("")
}

// Function to get SSL information
async function getSSLInfo(url) {
  try {
    const urlObj = new URL(url)

    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: urlObj.hostname,
          port: 443,
          path: "/",
          method: "HEAD",
          rejectUnauthorized: false, // Allow self-signed certificates
        },
        (res) => {
          const cert = res.socket.getPeerCertificate()

          if (Object.keys(cert).length > 0) {
            resolve({
              issuer: cert.issuer?.O || "Unknown",
              validFrom: new Date(cert.valid_from).toLocaleDateString(),
              validTo: new Date(cert.valid_to).toLocaleDateString(),
              fingerprint: cert.fingerprint || "Unknown",
            })
          } else {
            resolve(null)
          }
        },
      )

      req.on("error", (error) => {
        console.error("Error getting SSL info:", error)
        resolve(null)
      })

      req.end()
    })
  } catch (error) {
    console.error("Error getting SSL info:", error)
    return null
  }
}

// Function to analyze vulnerabilities
function analyzeVulnerabilities(html, headers, url) {
  const vulnerabilities = []

  // Check for missing security headers
  const securityHeaders = [
    { name: "Content-Security-Policy", header: "content-security-policy", severity: "medium" },
    { name: "X-Frame-Options", header: "x-frame-options", severity: "medium" },
    { name: "X-XSS-Protection", header: "x-xss-protection", severity: "medium" },
    { name: "X-Content-Type-Options", header: "x-content-type-options", severity: "low" },
    { name: "Strict-Transport-Security", header: "strict-transport-security", severity: "high" },
    { name: "Referrer-Policy", header: "referrer-policy", severity: "low" },
  ]

  securityHeaders.forEach((header) => {
    if (!headers[header.header]) {
      vulnerabilities.push({
        name: `Missing ${header.name} Header`,
        description: `The ${header.name} header is not set, which could expose the site to various attacks.`,
        severity: header.severity,
      })
    }
  })

  // Check for HTTP instead of HTTPS
  if (!url.startsWith("https://")) {
    vulnerabilities.push({
      name: "HTTP Instead of HTTPS",
      description: "The site is using HTTP instead of HTTPS, which means data is transmitted in clear text.",
      severity: "high",
    })
  }

  // Check for insecure cookies
  if (headers["set-cookie"]) {
    const cookieHeaders = Array.isArray(headers["set-cookie"]) ? headers["set-cookie"] : [headers["set-cookie"]]

    cookieHeaders.forEach((cookieStr) => {
      if (url.startsWith("https://") && !cookieStr.toLowerCase().includes("secure")) {
        vulnerabilities.push({
          name: "Insecure Cookies",
          description: "Cookies are set without the Secure flag, which means they can be transmitted over HTTP.",
          severity: "medium",
        })
      }

      if (!cookieStr.toLowerCase().includes("httponly")) {
        vulnerabilities.push({
          name: "Cookies Without HttpOnly",
          description: "Cookies are set without the HttpOnly flag, which means they can be accessed by JavaScript.",
          severity: "medium",
        })
      }
    })
  }

  // Check for outdated libraries
  const outdatedLibraries = [
    { pattern: /jquery-1\.[0-9]\./i, name: "jQuery < 2.0" },
    { pattern: /jquery-2\.[0-9]\./i, name: "jQuery < 3.0" },
    { pattern: /bootstrap-3\./i, name: "Bootstrap 3" },
    { pattern: /angular\.js\/1\.[2-5]\./i, name: "AngularJS < 1.6" },
    { pattern: /react-0\.1[0-4]\./i, name: "React < 0.15" },
  ]

  outdatedLibraries.forEach((lib) => {
    if (html.match(lib.pattern)) {
      vulnerabilities.push({
        name: "Outdated Library",
        description: `The site is using ${lib.name}, which may contain known vulnerabilities.`,
        severity: "medium",
      })
    }
  })

  return vulnerabilities
}

// Function to get IP information
async function getIpInfo(url) {
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname

    // Resolve IP address
    const addresses = await dns.resolve4(hostname)

    if (addresses && addresses.length > 0) {
      return {
        ip: addresses[0],
        hostname,
      }
    }

    return null
  } catch (error) {
    console.error("Error getting IP info:", error)
    return null
  }
}
// =============================================================
// == MITMWEB PROXY LAUNCHER CODE (APPENDED - Revised Path) ==
// =============================================================

let mitmwebProxyWindow = null // Use a distinct variable name

// --- Function to get the specific Mitmweb Path ---
// Uses the exact path provided by the user.
function getMitmwebPath() {
  // !!! Using the user-provided path directly !!!
  const mitmWebExecutablePath = path.join(__dirname, "mitmproxy", "bin", "mitmweb.exe")

  // Check if the specified file exists
  try {
    if (require("fs").existsSync(mitmWebExecutablePath)) {
      console.log(`Using configured mitmweb path: ${mitmWebExecutablePath}`)
      return mitmWebExecutablePath
    } else {
      console.error(`Configured mitmweb path does not exist: ${mitmWebExecutablePath}`)
      dialog.showErrorBox(
        "Mitmweb Not Found",
        `The specified mitmweb executable was not found at:\n${mitmWebExecutablePath}\n\nPlease ensure the path is correct and the file exists.`,
      )
      return null
    }
  } catch (err) {
    console.error(`Error checking mitmweb path (${mitmWebExecutablePath}):`, err)
    dialog.showErrorBox("File Access Error", `Could not verify the mitmweb path due to an error:\n${err.message}`)
    return null
  }
}

// --- New function to create and manage the mitmweb proxy window ---
function launchProxyWithMitmweb() {
  if (mitmwebProxyWindow && !mitmwebProxyWindow.isDestroyed()) {
    mitmwebProxyWindow.focus()
    console.log("Mitmweb proxy window already open. Focusing.")
    return
  }

  console.log("Creating new mitmweb proxy window...")

  // Get the specific mitmweb path *before* creating the window
  const mitmwebExePath = getMitmwebPath() // Get the configured path

  if (!mitmwebExePath) {
    console.error("Mitmweb executable path is invalid or not found. Cannot start proxy window.")
    // Error message is shown by getMitmwebPath()
    return // Stop if mitmweb isn't found/valid
  }

  mitmwebProxyWindow = new BrowserWindow({
    width: 1000, // Adjusted size
    height: 750,
    webPreferences: {
      preload: path.join(__dirname, "proxy.js"), // Use the corrected preload script
      webviewTag: true, // MUST be true to use <webview>
      contextIsolation: false, // Keep false if preload needs nodeIntegration
      nodeIntegration: true, // Keep true if preload uses require/node modules
    },
    show: false, // Don't show until ready and mitmweb is launched
    frame: false, // Use custom title bar from proxy.html
    titleBarStyle: "hidden",
    // parent: mainWindow, // Optional: makes it a child of the main window
    backgroundColor: "#1e1e2e", // Match CSS background
  })

  mitmwebProxyWindow.loadFile(path.join(__dirname, "proxy.html")) // Load the HTML file

  const mitmwebUrl = "http://127.0.0.1:8081" // Hardcoded URL mitmweb will listen on
  const psScriptPath = path.join(__dirname, "launch-mitmweb.ps1") // Path to your PowerShell script

  console.log(`Attempting to launch mitmweb using script: ${psScriptPath}`)
  console.log(`Using mitmweb executable path: ${mitmwebExePath}`)

  let psProcess
  try {
    // Execute the PowerShell script to launch mitmweb
    // The script will now open its own console window
    psProcess = spawn(
      "powershell.exe",
      [
        "-ExecutionPolicy",
        "Bypass",
        "-NoProfile",
        "-File",
        psScriptPath,
        "-MitmwebPath",
        mitmwebExePath, // Pass the executable path as a parameter
      ],
      {
        stdio: ["ignore", "pipe", "pipe"], // Still pipe stdout/stderr for logging in Electron console
      },
    )
  } catch (spawnError) {
    console.error("Failed to spawn PowerShell:", spawnError)
    dialog.showErrorBox("Proxy Launch Error", `Failed to start PowerShell process: ${spawnError.message}`)
    if (mitmwebProxyWindow && !mitmwebProxyWindow.isDestroyed()) {
      mitmwebProxyWindow.close() // Close the Electron window if spawning PowerShell failed
    }
    return
  }

  // --- Handle PowerShell Process Output (for logging, not control) ---
  let scriptOutput = "" // Collect output for potential error messages
  psProcess.stdout.on("data", (data) => {
    const output = data.toString().trim()
    if (output) {
      // Avoid logging empty lines
      scriptOutput += output + "\n"
      console.log(`PowerShell stdout: ${output}`)
    }
  })

  psProcess.stderr.on("data", (data) => {
    const errorOutput = data.toString().trim()
    if (errorOutput) {
      // Avoid logging empty lines
      scriptOutput += `ERROR: ${errorOutput}\n`
      console.error(`PowerShell stderr: ${errorOutput}`)
    }
  })

  psProcess.on("close", (code) => {
    console.log(`PowerShell script process (PID: ${psProcess.pid}) exited with code ${code}.`)
    // This indicates the script finished launching mitmweb (or failed).
    // Mitmweb itself runs independently in its own console now.
    if (code !== 0 && mitmwebProxyWindow && !mitmwebProxyWindow.isDestroyed()) {
      // If the script failed immediately (code != 0), show an error before window appears
      if (!mitmwebProxyWindow.isVisible()) {
        dialog.showErrorBox(
          "Proxy Launch Failed",
          `PowerShell script failed to launch mitmweb (code ${code}).\nCheck PowerShell console output for details.\n\nScript Output:\n${scriptOutput}`,
        )
        mitmwebProxyWindow.close() // Close the Electron window if launch failed
      } else {
        // If the window is already visible, the script exit might be less critical,
        // but could indicate an issue. Log it.
        console.warn(`PowerShell script exited with code ${code} after window was shown.`)
      }
    }
  })

  psProcess.on("error", (err) => {
    console.error("Error running PowerShell script:", err)
    if (mitmwebProxyWindow && !mitmwebProxyWindow.isDestroyed() && !mitmwebProxyWindow.isVisible()) {
      dialog.showErrorBox("Proxy Launch Error", `Failed to run PowerShell script: ${err.message}`)
      mitmwebProxyWindow.close()
    }
  })

  // --- Send URL to Renderer and Show Window ---
  // Wait for the window's content (HTML/CSS/JS) to finish loading
  mitmwebProxyWindow.webContents.once("did-finish-load", () => {
    console.log("Proxy window webContents loaded. Sending URL to renderer:", mitmwebUrl)
    // Send the URL ONLY AFTER the preload script is ready to receive it
    mitmwebProxyWindow.webContents.send("set-mitmweb-url", mitmwebUrl)

    // Show the window. Mitmweb console should appear separately.
    // A slight delay might still be good practice to ensure the mitmweb server is responsive.
    setTimeout(() => {
      if (mitmwebProxyWindow && !mitmwebProxyWindow.isDestroyed()) {
        mitmwebProxyWindow.show()
        console.log("Showing mitmweb proxy window.")
      }
    }, 750) // Increased delay slightly (adjust as necessary)
  })

  // --- Window Cleanup ---
  mitmwebProxyWindow.on("closed", () => {
    console.log("Mitmweb proxy window closed.")
    mitmwebProxyWindow = null

    // Attempt to terminate the mitmweb process (running in its own console)
    // when the Electron window closes. Targeting the PowerShell PID should kill its children too.
    if (psProcess && !psProcess.killed) {
      console.log(
        `Attempting to terminate PowerShell launcher process (PID: ${psProcess.pid}) and its children (mitmweb)...`,
      )
      try {
        if (process.platform === "win32") {
          // Forcefully kill the PowerShell process tree (/T kills children)
          spawn("taskkill", ["/PID", psProcess.pid, "/T", "/F"], { detached: true, stdio: "ignore" }).unref()
          console.log(`Sent taskkill /PID ${psProcess.pid} /T /F`)
        } else {
          // On Linux/macOS, send SIGTERM to the process group
          process.kill(-psProcess.pid, "SIGTERM") // Note the negative PID for process group
          console.log(`Sent SIGTERM to process group ${psProcess.pid}`)
          // Optional: Add a timeout and send SIGKILL if it doesn't terminate
          // setTimeout(() => { try { if (psProcess && !psProcess.killed) process.kill(-psProcess.pid, 'SIGKILL'); } catch(e){} }, 2000);
        }
      } catch (killErr) {
        // Catch errors if the process already exited
        if (killErr.code !== "ESRCH") {
          // ESRCH = No such process
          console.error("Failed to terminate mitmweb process tree:", killErr.message)
        } else {
          console.log("Process already terminated.")
        }
      }
    } else {
      console.log("PowerShell process was not found or already terminated.")
    }
  })
}

// --- IPC Handler to Trigger the New Proxy Window ---
// You should trigger THIS from your UI instead of the old 'open-proxy' or 'toggle-proxy'
ipcMain.on("open-mitmweb-proxy", () => {
  launchProxyWithMitmweb()
})

// =============================================================
// == END OF MITMWEB PROXY LAUNCHER CODE ==
// =============================================================





















































/**
 * ================================================================
 * Standalone Injection Tester IPC Handlers (Add to end of main.js)
 * ================================================================
 * This block provides the necessary ipcMain handlers required by
 * injection-tester.js (renderer process). Version 2: Improved Error Checks.
 */
;(() => {
  // Ensure necessary modules are available. Require them locally to this scope.
  const { ipcMain, net, dialog, app } = require("electron")
  const path = require("path")
  const fs = require("fs")
  const { URL, URLSearchParams } = require("url") // Use Node.js URL module

  console.log("[Injection Tester IPC] Initializing handlers...")

  // --- 1. Handler for getting the app path ---
  ipcMain.handle("get-app-path", async () => {
    console.log("[Injection Tester IPC] Received get-app-path request.")
    try {
      const appPath = app.getAppPath()
      console.log(`[Injection Tester IPC] Sending app path: ${appPath}`)
      return appPath
    } catch (error) {
      console.error("[Injection Tester IPC] Error in get-app-path handler:", error)
      throw error // Propagate error back to renderer
    }
  })
  console.log("[Injection Tester IPC] Registered get-app-path handler.")

  // --- 2. Handler for fetching URL content ---
  ipcMain.handle("fetch-url", async (event, args) => {
    console.log(`[Injection Tester IPC] Received fetch-url request for: ${args?.url}`)
    if (!args || !args.url) {
      console.error("[Injection Tester IPC] fetch-url: Missing URL argument.")
      throw new Error("URL argument is missing in fetch-url handler.")
    }

    const { url, headers = {}, cookies, timeout = 15000, followRedirects = true } = args
    const requestOptions = {
      method: "GET", // Assuming GET for initial fetch
      url: url,
      redirect: followRedirects ? "follow" : "manual", // Basic redirect handling
    }

    console.log(`[Injection Tester IPC] Fetching URL: ${requestOptions.url} (Timeout: ${timeout}ms)`)



    return new Promise((resolve, reject) => {
      const request = net.request(requestOptions)
      let responseBody = ""
      let finalUrl = url // Initialize finalUrl

      // Add provided headers
      if (headers) {
        for (const key in headers) {
          try {
            request.setHeader(key, headers[key])
            // console.log(`[Injection Tester IPC] Set Header: ${key}: ${headers[key].substring(0, 50)}...`); // Reduce noise
          } catch (headerError) {
            console.warn(`[Injection Tester IPC] Failed to set header ${key}: ${headerError.message}`)
          }
        }
      }
      // Add provided cookies (as a 'Cookie' header)
      if (cookies && cookies.Cookie) {
        // Check if the Cookie property exists
        try {
          request.setHeader("Cookie", cookies.Cookie) // Access the string value
          // console.log(`[Injection Tester IPC] Set Cookie header: ${cookies.Cookie.substring(0, 100)}...`); // Reduce noise
        } catch (cookieError) {
          console.warn(`[Injection Tester IPC] Failed to set Cookie header: ${cookieError.message}`)
        }
      }

      // Timeout handler
      const timeoutId = setTimeout(() => {
        console.error(`[Injection Tester IPC] Request timed out: ${url}`)
        request.abort()
        reject(new Error(`Request timed out after ${timeout}ms`))
      }, timeout)

      request.on("response", (response) => {
        clearTimeout(timeoutId) // Clear timeout on response
        // console.log(`[Injection Tester IPC] Received response: ${response.statusCode} from ${response.url || url}`); // Reduce noise
        finalUrl = response.url || finalUrl // Update final URL based on response

        response.on("data", (chunk) => {
          responseBody += chunk.toString()
        })

        response.on("end", () => {
          // console.log(`[Injection Tester IPC] Fetch finished for: ${finalUrl}. Body length: ${responseBody.length}`); // Reduce noise
          if (response.statusCode >= 200 && response.statusCode < 400) {
            // Accept 2xx and 3xx
            resolve({ body: responseBody, finalUrl: finalUrl })
          } else {
            console.error(`[Injection Tester IPC] HTTP error ${response.statusCode} for ${finalUrl}`)
            reject(new Error(`HTTP Error: ${response.statusCode}. Body length: ${responseBody.length}`))
          }
        })

        response.on("error", (error) => {
          clearTimeout(timeoutId)
          console.error("[Injection Tester IPC] Response error:", error)
          reject(error)
        })
      })

      request.on("redirect", (statusCode, method, redirectUrl, responseHeaders) => {
        console.log(`[Injection Tester IPC] Redirecting (${statusCode}) to: ${redirectUrl}`)
        finalUrl = redirectUrl // Update final URL on redirect event
      })

      request.on("error", (error) => {
        clearTimeout(timeoutId)
        console.error("[Injection Tester IPC] Request error:", error)
        reject(error)
      })

      request.end() // Send the request
    })
  })
  console.log("[Injection Tester IPC] Registered fetch-url handler.")

  // --- 3. Handler for sending the actual test request ---
  ipcMain.handle("send-test-request", async (event, args) => {
    // --- Improved Argument Validation ---
    const missingArgs = []
    if (!args) {
      missingArgs.push("entire args object")
    }else {
      if (!args.testType) missingArgs.push("testType")
      if (!args.targetUrl) missingArgs.push("targetUrl")
      if (!args.method) missingArgs.push("method")
      if (!args.paramName) missingArgs.push("paramName")
      if (typeof args.payload === "undefined") missingArgs.push("payload")
      // Check 'allParams' specifically - must exist and be an array
      if (!args.allParams || !Array.isArray(args.allParams)) missingArgs.push("allParams (must be an array)")
    }

    if (missingArgs.length > 0) {
      const errorMsg = `Missing/Invalid required arguments for send-test-request: ${missingArgs.join(", ")}.`
      console.error(`[Injection Tester IPC] send-test-request Error: ${errorMsg}`)
      console.error(
        `[Injection Tester IPC] >> Args received (partial): testType=${args?.testType}, targetUrl=${args?.targetUrl}, method=${args?.method}, paramName=${args?.paramName}, payloadDefined=${typeof args?.payload !== "undefined"}, allParamsType=${typeof args?.allParams}, allParamsIsArray=${Array.isArray(args?.allParams)}`,
      )
      throw new Error(`Missing/Invalid required arguments: ${missingArgs.join(", ")}`) // Throw specific error
    }
    // --- End Improved Argument Validation ---

    // console.log(`[Injection Tester IPC] Received send-test-request for param "${args.paramName}" on ${args.targetUrl}`); // Reduce noise

    const {
      testType,
      targetUrl,
      method,
      paramName,
      payload,
      allParams, // Now validated to be an array
      testAllParamsTogether, // Boolean
      headers = {},
      cookies,
      timeout = 5000, // Shorter timeout for individual tests
      followRedirects = false, // Usually DON'T follow redirects for vuln testing
    } = args

    let requestUrl = targetUrl
    let requestBody = null
    const requestMethod = method.toUpperCase()
    const requestHeaders = { ...headers } // Copy headers

    try {
      const urlObject = new URL(targetUrl) // Use URL for easier manipulation

      // --- Craft Request URL and Body ---
      if (requestMethod === "GET") {
        // Base search params on the original URL's search params
        const searchParams = new URLSearchParams(urlObject.search)
        // Clear specific params we will set
        if (!testAllParamsTogether) {
          // If NOT testing all together, remove existing params first
          allParams.forEach((param) => searchParams.delete(param.name))
        }
        // Set parameters
        allParams.forEach((param) => {
          if (param.name === paramName) {
            searchParams.set(param.name, payload) // Inject payload
          } else if (testAllParamsTogether) {
            // Only set other params if testing all together
            searchParams.set(param.name, "") // Placeholder value - needs refinement
          }
        })
        // If not testing all together, ensure only the tested param is present (already handled by delete+set logic)
        urlObject.search = searchParams.toString() // Assign potentially modified params
        requestUrl = urlObject.toString()
      } else if (requestMethod === "POST") {
        // Prepare POST body (assume application/x-www-form-urlencoded by default)
        const postParams = new URLSearchParams()
        allParams.forEach((param) => {
          if (param.name === paramName) {
            postParams.set(param.name, payload)
          } else if (testAllParamsTogether) {
            postParams.set(param.name, "") // Placeholder value
          }
        })
        // Set Content-Type if not already provided
        if (!requestHeaders["Content-Type"]) {
          requestHeaders["Content-Type"] = "application/x-www-form-urlencoded"
        }
        requestBody = postParams.toString()
        requestHeaders["Content-Length"] = Buffer.byteLength(requestBody).toString()
      } else {
        throw new Error(`Unsupported request method: ${requestMethod}`)
      }
      // --- End Crafting ---

      // console.log(`[Injection Tester IPC] Sending Test (${testType}): ${requestMethod} ${requestUrl}`); // Reduce noise
      // if(requestBody) console.log(`[Injection Tester IPC] > Body: ${requestBody.substring(0,100)}...`); // Reduce noise

      // --- Send Request using net ---
      const requestOptions = {
        method: requestMethod,
        url: requestUrl,
        redirect: followRedirects ? "follow" : "manual",
      }

      return new Promise((resolve, reject) => {
        const request = net.request(requestOptions)
        let responseBody = ""
        let responseHeaders = {}
        let responseStatusCode = 0
        let finalRequestUrl = requestUrl

        // Add headers
        for (const key in requestHeaders) {
          try {
            request.setHeader(key, requestHeaders[key])
          } catch (e) {
            console.warn(`Failed to set header ${key}: ${e.message}`)
          }
        }
        // Add cookies
        if (cookies && cookies.Cookie) {
          // Check property exists
          try {
            request.setHeader("Cookie", cookies.Cookie)
          } catch (e) {
            console.warn(`Failed to set Cookie header: ${e.message}`)
          }
        }

        // Timeout
        const timeoutId = setTimeout(() => {
          console.error(`[Injection Tester IPC] Test request timed out: ${requestUrl}`)
          request.abort()
          reject(new Error(`Test request timed out after ${timeout}ms`))
        }, timeout)

        request.on("response", (response) => {
          clearTimeout(timeoutId)
          responseStatusCode = response.statusCode
          responseHeaders = response.headers
          finalRequestUrl = response.url || finalRequestUrl
          // console.log(`[Injection Tester IPC] Test Response: ${responseStatusCode} from ${finalRequestUrl}`); // Reduce noise

          response.on("data", (chunk) => {
            responseBody += chunk.toString()
          })

          response.on("end", () => {
            // console.log(`[Injection Tester IPC] Test finished. Body length: ${responseBody.length}`); // Reduce noise
            // --- Basic Vulnerability Detection Logic ---
            let vulnerable = false
            let severity = "Low" // Default severity
            let details = "No vulnerability detected."

            try {
              if (testType === "xss") {
                // Basic Reflected XSS Check: Does the payload appear unescaped?
                if (responseBody.includes(payload)) {
                  // Avoid matching if payload is simple/numeric/common or overly long response
                  if (payload.length > 3 && responseBody.length < 500000 && /[<>"'`]/.test(payload)) {
                    // Added regex check for common XSS chars
                    // More advanced: check if it's outside typical escaping contexts if possible
                    vulnerable = true
                    severity = "Medium" // Upgrade severity based on chars
                    details = `Payload reflected in response body. Manual verification required. Found at index: ${responseBody.indexOf(payload)}`
                    // console.log(`[Injection Tester IPC] Potential XSS detected for param ${paramName}`); // Reduce noise
                  } else if (payload.length <= 3 && responseBody.includes(payload)) {
                    // Very short payloads reflecting might be less indicative
                    details = `Payload reflected but is very short (${payload.length} chars). Manual check needed.`
                    severity = "Info"
                  }
                }
              } else if (testType === "sqli") {
                // Basic Error-Based SQLi Check: Look for common SQL error patterns.
                const sqlErrors = [
                  "syntax error near",
                  "sql syntax",
                  "unclosed quotation mark",
                  "you have an error in your sql syntax",
                  "mysql_fetch",
                  "invalid sql",
                  "pg_query",
                  "ora-0",
                  "odbc driver error",
                  "incorrect syntax near",
                  "quoted string not properly terminated",
                ]
                if (sqlErrors.some((error) => responseBody.toLowerCase().includes(error))) {
                  vulnerable = true
                  severity = "High"
                  details = `Potential SQL error detected in response. Manual verification required.`
                  // console.log(`[Injection Tester IPC] Potential SQLi detected for param ${paramName}`); // Reduce noise
                }
              } else if (testType === "cmdi") {
                details = "CMDi detection logic not implemented in this basic handler."
              } else {
                details = `${testType.toUpperCase()} detection logic not implemented.`
              }
            } catch (detectionError) {
              console.error(`[Injection Tester IPC] Error during vulnerability detection: ${detectionError}`)
              details = `Error during detection: ${detectionError.message}`
            }

            resolve({
              vulnerable: vulnerable,
              severity: severity,
              details: details,
              requestUrl: finalRequestUrl,
            })
          })
          response.on("error", (error) => {
            clearTimeout(timeoutId)
            console.error("[Injection Tester IPC] Test Response error:", error)
            reject(error)
          })
        })

        request.on("redirect", (statusCode, method, redirectUrl, responseHeaders) => {
          console.log(`[Injection Tester IPC] Test Redirect (${statusCode}) to: ${redirectUrl}`)
          finalRequestUrl = redirectUrl // Update final request URL on redirect event
        })

        request.on("error", (error) => {
          clearTimeout(timeoutId)
          console.error("[Injection Tester IPC] Test Request error:", error)
          reject(error)
        })

        // Write POST body if it exists
        if (requestBody) {
          request.write(requestBody)
        }
        request.end() // Send the request
      }) // End Promise
    } catch (error) {
      console.error(`[Injection Tester IPC] Error constructing test request for ${paramName}:`, error)
      // Throw error back to renderer to be handled
      throw error
    }
  })
  console.log("[Injection Tester IPC] Registered send-test-request handler.")

  // --- 4. Handler for Save File Dialog (using fs.promises) ---
  ipcMain.handle("save-file-dialog", async (event, args) => {
    console.log("[Injection Tester IPC] Received save-file-dialog request.")
    if (!args || typeof args.content === "undefined") {
      console.error("[Injection Tester IPC] save-file-dialog: Missing required arguments (content).")
      throw new Error("Missing required arguments (content) for save-file-dialog.")
    }

    const {
      title = "Save File",
      defaultPath = "export.txt",
      filters = [{ name: "All Files", extensions: ["*"] }],
      content,
    } = args

    try {
      const window = require("electron").BrowserWindow.fromWebContents(event.sender)
      if (!window) {
        console.error("[Injection Tester IPC] Could not find browser window for save dialog.")
        // Attempt without parent window as fallback
        const { canceled, filePath } = await dialog.showSaveDialog({ title, defaultPath, filters })
        if (canceled || !filePath) {
          /* Handle cancellation/error */ throw new Error("Save dialog failed or was cancelled.")
        }
        console.log(`[Injection Tester IPC] Saving file to: ${filePath}`)
        await fs.promises.writeFile(filePath, content, "utf8")
        console.log("[Injection Tester IPC] File saved successfully.")
        return { success: true, canceled: false, filePath: filePath }
      } else {
        // Show dialog attached to the window
        const { canceled, filePath } = await dialog.showSaveDialog(window, { title, defaultPath, filters })
        if (canceled || !filePath) {
          console.log("[Injection Tester IPC] Save dialog cancelled by user.")
          return { success: false, canceled: true }
        }
        console.log(`[Injection Tester IPC] Saving file to: ${filePath}`)
        await fs.promises.writeFile(filePath, content, "utf8")
        console.log("[Injection Tester IPC] File saved successfully.")
        return { success: true, canceled: false, filePath: filePath }
      }
    } catch (error) {
      console.error(`[Injection Tester IPC] Error during file save: ${error.message}`)
      // Don't return the error object itself via IPC for security/stability
      return { success: false, canceled: false, error: `File save failed: ${error.message}` }
    }
  })
  console.log("[Injection Tester IPC] Registered save-file-dialog handler.")

  // --- ADDED: Handler for the Export Results (save-results) ---
  // This specifically handles saving the results array, usually as JSON
  ipcMain.handle("save-results", async (event, args) => {
    console.log("[Injection Tester IPC] Received save-results request.")
    if (!args || !args.results || !Array.isArray(args.results)) {
      console.error("[Injection Tester IPC] save-results: Missing or invalid results array.")
      throw new Error("Missing or invalid results array for save-results.")
    }

    const { defaultPath = "results.json", results, format = "json" } = args // Default to JSON
    let fileContent = ""
    let fileFilters = [{ name: "JSON Files", extensions: ["json"] }]

    try {
      if (format.toLowerCase() === "json") {
        fileContent = JSON.stringify(results, null, 2) // Pretty print JSON
      } else if (format.toLowerCase() === "csv") {
        // Basic CSV implementation (matches renderer export attempt)
        const csvHeader = "ID,Timestamp,Type,Severity,URL,Parameter,Payload,Details\n"
        const csvRows = results
          .map((r) =>
            [
              r.id,
              r.timestamp, // Already ISO string usually
              r.type,
              r.severity,
              `"${(r.url || "").replace(/"/g, '""')}"`, // Escape quotes
              `"${(r.param || "").replace(/"/g, '""')}"`,
              `"${(r.payload || "").replace(/"/g, '""')}"`,
              `"${(r.details || "").replace(/"/g, '""')}"`,
            ].join(","),
          )
          .join("\n")
        fileContent = csvHeader + csvRows
        fileFilters = [{ name: "CSV Files", extensions: ["csv"] }]
      } else {
        throw new Error(`Unsupported export format: ${format}`)
      }
    } catch (formatError) {
      console.error(`[Injection Tester IPC] Error formatting results: ${formatError}`)
      throw formatError
    }

    // Use the generic save-file-dialog logic (or repeat it here if preferred)
    try {
      const window = require("electron").BrowserWindow.fromWebContents(event.sender)
      const options = {
        title: "Save Test Results",
        defaultPath: defaultPath,
        filters: fileFilters,
      }

      const { canceled, filePath } = window
        ? await dialog.showSaveDialog(window, options)
        : await dialog.showSaveDialog(options) // Fallback if no window

      if (canceled || !filePath) {
        console.log("[Injection Tester IPC] Save results cancelled.")
        return null // Return null or similar indication of cancellation
      }

      await fs.promises.writeFile(filePath, fileContent, "utf8")
      console.log(`[Injection Tester IPC] Results saved successfully to ${filePath}`)
      return filePath // Return the path on success
    } catch (saveError) {
      console.error(`[Injection Tester IPC] Error saving results file: ${saveError}`)
      throw saveError // Let the renderer handle the error
    }
  })
  console.log("[Injection Tester IPC] Registered save-results handler.")
})() // Immediately invoke the function scope
/**
 * ================================================================
 * End of Standalone Injection Tester IPC Handlers
 * ================================================================
 */



















/**
 * =======================================================================
 * Standalone ParamHunter Tool IPC Handlers (Add to end of main.js)
 * =======================================================================
 * Handles window creation, URL fetching, and file saving for ParamHunter.
 */
;(() => {
  // Ensure necessary modules are available
  const { BrowserWindow, ipcMain, dialog, session, net } = require('electron');
  const path = require('path');
  const fs = require('fs').promises;
  const https = require('https');
  const http = require('http');

  // Declare window variable within this scope
  let paramhunterWindow = null;

  console.log('[ParamHunter IPC] Initializing handlers...');

  // --- Function to Create ParamHunter Window ---
  function createParamHunterWindow() {
      if (paramhunterWindow && !paramhunterWindow.isDestroyed()) {
          console.log('[ParamHunter IPC] Window already exists, focusing.');
          paramhunterWindow.focus();
          return;
      }

      console.log('[ParamHunter IPC] Creating ParamHunter window...');
      paramhunterWindow = new BrowserWindow({
          width: 1200, // Similar size to injection tester
          height: 800,
          minWidth: 900,
          minHeight: 600,
          frame: false, // Use custom titlebar
          resizable: true,
          webPreferences: {
              nodeIntegration: true, // Required for require in paramhunter.js
              contextIsolation: false, // Required for nodeIntegration
          },
          titleBarStyle: 'hidden',
          show: false, // Don't show until ready-to-show event
          icon: path.join(__dirname, 'icon.ico'), // Ensure icon path is correct
          backgroundColor: '#1e1e2e', // Match CSS
      });

      paramhunterWindow.loadFile(path.join(__dirname, 'paramhunter.html')); // Load the tool's HTML

      paramhunterWindow.once('ready-to-show', () => {
          paramhunterWindow.show();
          console.log('[ParamHunter IPC] ParamHunter window ready and shown.');
      });

      paramhunterWindow.on('closed', () => {
          console.log('[ParamHunter IPC] ParamHunter window closed.');
          paramhunterWindow = null; // Clear reference
      });
  }

  // --- IPC Handlers ---

  // 1. Open ParamHunter Window (Listener from arsenal.js)
  ipcMain.on('open-paramhunter', () => {
      console.log('[ParamHunter IPC] Received request to open window via open-paramhunter.');
      createParamHunterWindow();
  });
  console.log("[ParamHunter IPC] Registered 'open-paramhunter' listener.");

  // 2. Fetch URL Content (Needed by paramhunter.js)
  ipcMain.handle('paramhunter:fetch-url', async (event, args) => {
      // console.log(`[ParamHunter IPC] Received fetch-url request for: ${args?.url}`); // Verbose
      if (!args || !args.url) {
          console.error("[ParamHunter IPC] fetch-url: Missing URL argument.")
          throw new Error("URL argument is missing in paramhunter:fetch-url handler.")
      }

      const { url, headers = {}, cookies, timeout = 10000, followRedirects = true } = args
      const requestOptions = {
          method: "GET",
          url: url,
          redirect: followRedirects ? 'follow' : 'manual',
          useSessionCookies: false // Don't use browser session cookies for this tool
      }

      // console.log(`[ParamHunter IPC] Fetching: ${requestOptions.url} (Timeout: ${timeout}ms)`); // Verbose

      return new Promise((resolve, reject) => {
          const request = net.request(requestOptions)
          let responseBody = ''
          let finalUrl = url
          let statusCode = 0
          let responseHeaders = {}

          // Add provided headers
          for (const key in headers) {
              try { request.setHeader(key, headers[key]); }
              catch (headerError) { console.warn(`[ParamHunter IPC] Failed to set header ${key}: ${headerError.message}`); }
          }
          // Add provided cookies
          if (cookies && cookies.Cookie) {
              // Check property exists
              try { request.setHeader('Cookie', cookies.Cookie); }
              catch (cookieError) { console.warn(`[ParamHunter IPC] Failed to set Cookie header: ${cookieError.message}`); }
          }

          const timeoutId = setTimeout(() => {
              console.error(`[ParamHunter IPC] Request timed out: ${url}`)
              request.abort()
              reject(new Error(`Request timed out after ${timeout}ms`))
          }, timeout)

          request.on('response', (response) => {
              clearTimeout(timeoutId)
              finalUrl = response.url || finalUrl // Might change with redirects
              statusCode = response.statusCode
              responseHeaders = response.headers

              response.on('data', (chunk) => {
                  // Limit response body size to prevent memory issues
                  if (responseBody.length < 10 * 1024 * 1024) { // Limit to ~10MB
                      responseBody += chunk.toString()
                  } else {
                      if (!request.isDestroyed()) {
                            request.abort() // Abort if too large
                            console.warn(`[ParamHunter IPC] Aborted fetch for ${finalUrl} due to excessive size (>10MB)`)
                            reject(new Error("Response body exceeded size limit (10MB)"))
                      }
                  }
              });

              response.on('end', () => {
                  // console.log(`[ParamHunter IPC] Fetch finished for: ${finalUrl}. Status: ${statusCode}. Body length: ${responseBody.length}`); // Reduce noise
                  resolve({ body: responseBody, finalUrl: finalUrl, statusCode: statusCode, headers: responseHeaders })
              });

              response.on('error', (error) => {
                  clearTimeout(timeoutId)
                  console.error("[ParamHunter IPC] Response error:", error)
                  reject(error)
              })
          });

          request.on('redirect', (statusCode, method, redirectUrl, responseHeaders) => {
              console.log(`[ParamHunter IPC] Redirecting (${statusCode}) to: ${redirectUrl}`)
              finalUrl = redirectUrl // Update final URL on redirect event
          });

          request.on('error', (error) => {
              clearTimeout(timeoutId)
              console.error("[ParamHunter IPC] Request error:", error)
              reject(error)
          });

          request.end() // Send the request
      });
  });
  console.log("[ParamHunter IPC] Registered 'paramhunter:fetch-url' handler.");


  // 3. Save Results File Dialog (Needed by paramhunter.js)
  ipcMain.handle('paramhunter:save-results', async (event, args) => {
      console.log("[ParamHunter IPC] Received save-results request.")
      if (!args || !args.results || !Array.isArray(args.results)) {
          console.error("[ParamHunter IPC] save-results: Missing or invalid results array.")
          throw new Error("Missing or invalid results array for paramhunter:save-results.")
      }

      const { defaultPath = "paramhunter_results.json", results, format = "json" } = args;
      let fileContent = "";
      let fileFilters = [{ name: "JSON Files", extensions: ["json"] }];

      try {
          if (format.toLowerCase() === "json") {
              fileContent = JSON.stringify(results, null, 2); // Pretty print JSON
          } else if (format.toLowerCase() === "csv") {
              // Basic CSV implementation
              const csvHeader = "ID,Found URL,Parameter Name,Source,Potential Vuln Tags,Timestamp\n";
              const csvRows = results.map(r => [
                      r.id,
                      `"${(r.url || "").replace(/"/g, '""')}"`,
                      `"${(r.paramName || "").replace(/"/g, '""')}"`,
                      `"${(r.source || "").replace(/"/g, '""')}"`,
                      `"${(r.tags || []).join(';').replace(/"/g, '""')}"`, // Join tags with semicolon
                      r.timestamp ? new Date(r.timestamp).toISOString() : ''
                  ].join(",")
              ).join("\n");
              fileContent = csvHeader + csvRows
              fileFilters = [{ name: "CSV Files", extensions: ["csv"] }]
          } else {
              throw new Error(`Unsupported export format: ${format}`)
          }
      } catch (formatError) {
          console.error(`[ParamHunter IPC] Error formatting results: ${formatError}`)
          throw formatError
      }

      try {
          // Use the ParamHunter window as parent for the dialog if available
          const window = paramhunterWindow && !paramhunterWindow.isDestroyed()
                           ? paramhunterWindow
                           : BrowserWindow.fromWebContents(event.sender); // Fallback to sender's window

          const options = {
              title: "Save ParamHunter Results",
              defaultPath: defaultPath,
              filters: fileFilters,
          };

          const { canceled, filePath } = window
              ? await dialog.showSaveDialog(window, options)
              : await dialog.showSaveDialog(options); // Fallback if no window

          if (canceled || !filePath) {
              console.log("[ParamHunter IPC] Save results cancelled.")
              return null // Indicate cancellation
          }

          await fs.writeFile(filePath, fileContent, 'utf8');
          console.log(`[ParamHunter IPC] Results saved successfully to ${filePath}`);
          return filePath; // Return the path on success
      } catch (saveError) {
          console.error(`[ParamHunter IPC] Error saving results file: ${saveError}`)
          throw saveError; // Let the renderer handle the error
      }
  });
  console.log("[ParamHunter IPC] Registered 'paramhunter:save-results' handler.");


  // 4. Window Controls (Minimize/Close for ParamHunter Window)
  ipcMain.on('paramhunter:minimize-window', (event) => {
      const window = paramhunterWindow || BrowserWindow.fromWebContents(event.sender);
      if (window && !window.isDestroyed()) {
          console.log('[ParamHunter IPC] Minimizing ParamHunter window.');
          window.minimize();
      }
  });
  ipcMain.on('paramhunter:close-window', (event) => {
      const window = paramhunterWindow || BrowserWindow.fromWebContents(event.sender);
      if (window && !window.isDestroyed()) {
          console.log('[ParamHunter IPC] Closing ParamHunter window.');
          window.close(); // Triggers 'closed' event defined above
      }
  });
  console.log("[ParamHunter IPC] Registered ParamHunter window controls.");

})(); // Immediately invoke the function scope
/**
 * =======================================================================
 * End of Standalone ParamHunter Tool IPC Handlers
 * =======================================================================
 */

































/**
 * ================================================================
 * Standalone XSS Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the xxsspider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let xssSpiderProcess = null;

  function startXssSpider(win, opts) {
    if (xssSpiderProcess) {
      win.webContents.send('xss-spider:log', 'XSS Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'xxsspider.js');
    xssSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    xssSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`xss-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    xssSpiderProcess.on('exit', () => { xssSpiderProcess = null; });
    xssSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('xss-spider:status', 'Running');
  }

  function stopXssSpider(win) {
    if (xssSpiderProcess) {
      xssSpiderProcess.send({ type: 'stop' });
      xssSpiderProcess.kill();
      xssSpiderProcess = null;
      win.webContents.send('xss-spider:status', 'Stopped');
    }
  }

  ipcMain.on('xss-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopXssSpider(win); // Always stop any previous process before starting a new one
    startXssSpider(win, opts);
  });
  ipcMain.on('xss-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopXssSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (xssSpiderProcess) {
        xssSpiderProcess.kill();
        xssSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone SQLi Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the sqli_spider_engine.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let sqliSpiderProcess = null;

  function startSqliSpider(win, opts) {
    if (sqliSpiderProcess) {
      win.webContents.send('sqli-spider:log', 'SQLi Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'sqli_spider_engine.js');
    sqliSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    sqliSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`sqli-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    sqliSpiderProcess.on('exit', () => { sqliSpiderProcess = null; });
    sqliSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('sqli-spider:status', 'Running');
  }

  function stopSqliSpider(win) {
    if (sqliSpiderProcess) {
      sqliSpiderProcess.send({ type: 'stop' });
      sqliSpiderProcess.kill();
      sqliSpiderProcess = null;
      win.webContents.send('sqli-spider:status', 'Stopped');
    }
  }

  ipcMain.on('sqli-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopSqliSpider(win); // Always stop any previous process before starting a new one
    startSqliSpider(win, opts);
  });
  ipcMain.on('sqli-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopSqliSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (sqliSpiderProcess) {
        sqliSpiderProcess.kill();
        sqliSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone IDOR Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the idorspider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let idorSpiderProcess = null;

  function startIdorSpider(win, opts) {
    if (idorSpiderProcess) {
      win.webContents.send('idor-spider:log', 'IDOR Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'idorspider.js');
    idorSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    idorSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`idor-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    idorSpiderProcess.on('exit', () => { idorSpiderProcess = null; });
    idorSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('idor-spider:status', 'Running');
  }

  function stopIdorSpider(win) {
    if (idorSpiderProcess) {
      idorSpiderProcess.send({ type: 'stop' });
      idorSpiderProcess.kill();
      idorSpiderProcess = null;
      win.webContents.send('idor-spider:status', 'Stopped');
    }
  }

  ipcMain.on('idor-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopIdorSpider(win); // Always stop any previous process before starting a new one
    startIdorSpider(win, opts);
  });
  ipcMain.on('idor-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopIdorSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (idorSpiderProcess) {
        idorSpiderProcess.kill();
        idorSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone WordPress Recon Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the wordpressReconSpider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let wordpressReconSpiderProcess = null;

  function startWordpressReconSpider(win, opts) {
    if (wordpressReconSpiderProcess) {
      win.webContents.send('wordpressrecon-spider:log', 'WordPress Recon Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'wordpressReconSpider.js');
    wordpressReconSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    wordpressReconSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`wordpressrecon-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    wordpressReconSpiderProcess.on('exit', () => { wordpressReconSpiderProcess = null; });
    wordpressReconSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('wordpressrecon-spider:status', 'Running');
  }

  function stopWordpressReconSpider(win) {
    if (wordpressReconSpiderProcess) {
      wordpressReconSpiderProcess.send({ type: 'stop' });
      wordpressReconSpiderProcess.kill();
      wordpressReconSpiderProcess = null;
      win.webContents.send('wordpressrecon-spider:status', 'Stopped');
    }
  }

  ipcMain.on('wordpressrecon-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopWordpressReconSpider(win); // Always stop any previous process before starting a new one
    startWordpressReconSpider(win, opts);
  });
  ipcMain.on('wordpressrecon-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopWordpressReconSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (wordpressReconSpiderProcess) {
        wordpressReconSpiderProcess.kill();
        wordpressReconSpiderProcess = null;
      }
    });
  }
})();

// IPC handler for CAD tool (standalone)
// const { ipcMain } = require('electron');
// ipcMain.handle('cad-operation', async (event, { op, input, key }) => {
//     // Implement the same logic as in cad.js for backend/secure operations if needed
//     // For now, just a placeholder for future IPC expansion
//     return { result: 'Not implemented in main process. Use frontend.' };
// });

/**
 * ================================================================
 * Standalone Burp Suite Launcher IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles launching Burp Suite Community Edition in a themed Electron window.
 */
;(() => {
  const { BrowserWindow, ipcMain } = require('electron');
  const path = require('path');
  const { spawn } = require('child_process');
  let burpWindow = null;
  let burpProcess = null;

  function createBurpSuiteWindow() {
    if (burpWindow && !burpWindow.isDestroyed()) {
      burpWindow.focus();
      return;
    }
    burpWindow = new BrowserWindow({
      width: 1200,
      height: 800,      minWidth: 900,
      minHeight: 600,
      frame: false,
      resizable: true,
      webPreferences: {
        nodeIntegration: true,
        contextIsolation: false,
      },
      titleBarStyle: 'hidden',
      show: false,
      title: 'WebSlinger',
      icon: path.join(__dirname, 'images', 'webslinger.ico'),
      backgroundColor: '#1e1e2e',
    });
    burpWindow.loadFile(path.join(__dirname, 'burpsuite.html'));
    burpWindow.once('ready-to-show', () => {
      burpWindow.show();      // Launch Burp Suite Community Edition as a child process
      if (!burpProcess || burpProcess.killed) {
        const exePath = path.join(__dirname, 'resources', 'app.asar', 'BurpSuiteCommunity', 'BurpSuiteCommunity.exe');
        try {
          burpProcess = spawn(exePath, [], { detached: true, stdio: 'ignore' });
          burpProcess.unref();
        } catch (error) {
          console.error('Failed to launch Burp Suite:', error);
          burpWindow.webContents.send('burp-error', 'Failed to launch Burp Suite. Please check the installation.');
        }
      }
    });
    burpWindow.on('closed', () => {
      burpWindow = null;
      // Optionally, kill Burp process if you want to close it with the window
      // if (burpProcess && !burpProcess.killed) burpProcess.kill();
    });
  }
  ipcMain.on('open-burpsuite', () => {
    createBurpSuiteWindow();
  });
})();

// --- AI Chatbot IPC Handler ---
ipcMain.handle('ai:chat', async (event, payload) => {
  return new Promise((resolve, reject) => {
    const python = process.platform === "win32" ? "python" : "python3";





    const path = require("path");
const isPackaged = require("electron").app ? require("electron").app.isPackaged : false;
let scriptPath;
if (isPackaged) {
  // In production, __dirname is inside resources/app.asar, but keytest.py should be in resources/
  scriptPath = path.join(process.resourcesPath, "keytest.py");
  
} else {
  // In dev, __dirname is project root
  scriptPath = path.join(__dirname, "keytest.py");
}





    // Pass payload as JSON string (includes chat_memory, history_id, file_data)
    const proc = spawn(python, [scriptPath, JSON.stringify(payload)]);
    let output = "";
    let error = "";

    proc.stdout.on("data", (data) => {
      output += data.toString();
    });
    proc.stderr.on("data", (data) => {
      error += data.toString();
    });
    proc.on("close", (code) => {
      // Output is always JSON string: {response, history_id}
      try {
        const out = JSON.parse(output.trim());
        resolve(out);
      } catch {
        resolve({ response: "[API error or connection error]", history_id: payload && payload.history_id });
      }
    });
    proc.on("error", (err) => {
      resolve({ response: "[API error or connection error]", history_id: payload && payload.history_id });
    });
  });
});

// Add this handler near other ipcMain.on handlers
ipcMain.on('open-arsenal', () => {
  toggleArsenal();
});

// --- AGENT: Get active tab content from renderer ---
ipcMain.handle('agent:get-active-tab-content', async (event) => {
  // Forward the request to the main window (renderer)
  if (!mainWindow || mainWindow.isDestroyed()) return { error: "No main window" };
  return new Promise((resolve) => {
    // Listen for the reply only once
    ipcMain.once('agent:active-tab-content-response', (evt, data) => {
      resolve(data);
    });
    mainWindow.webContents.send('agent:get-active-tab-content');
  });
});

// --- AI Spider IPC Handler ---
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let aiSpiderProcess = null;

  function startAiSpider(win, opts) {
    if (aiSpiderProcess) stopAiSpider(win);
    const scriptPath = path.join(__dirname, 'ai_spider.js');
    aiSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    aiSpiderProcess.on('message', (msg) => {
      // Forward all AI spider messages to the renderer
      if (win && !win.isDestroyed()) {
        if (msg.type === 'ai_report') {
          win.webContents.send('ai-spider:report', msg.data);
        } else if (msg.type === 'finding') {
          win.webContents.send('ai-spider:finding', msg.data);
        } else if (msg.type === 'progress') {
          win.webContents.send('ai-spider:progress', msg.data);
        } else if (msg.type === 'ai_spider_done') {
          win.webContents.send('ai-spider:done');
        }
      }
    });
    aiSpiderProcess.on('exit', () => {
      aiSpiderProcess = null;
      if (win && !win.isDestroyed()) {
        win.webContents.send('ai-spider:status', 'Stopped');
      }
    });
    aiSpiderProcess.send({ type: 'ai_spider_start', data: opts });
    win.webContents.send('ai-spider:status', 'Running');
  }

  function stopAiSpider(win) {
    if (aiSpiderProcess) {
      aiSpiderProcess.send({ type: 'ai_spider_stop' });
      aiSpiderProcess.kill();
      aiSpiderProcess = null;
      if (win && !win.isDestroyed()) {
        win.webContents.send('ai-spider:status', 'Stopped');
      }
    }
  }

  ipcMain.on('ai-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopAiSpider(win);
    startAiSpider(win, opts);
  });
  ipcMain.on('ai-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopAiSpider(win);
  });
})();

/**
 * ================================================================
 * Standalone Open Redirect Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the openredirectspider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let openredirectSpiderProcess = null;

  function startOpenRedirectSpider(win, opts) {
    if (openredirectSpiderProcess) {
      win.webContents.send('openredirect-spider:log', 'Open Redirect Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'openredirectspider.js');
    openredirectSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    openredirectSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`openredirect-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    openredirectSpiderProcess.on('exit', () => { openredirectSpiderProcess = null; });
    openredirectSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('openredirect-spider:status', 'Running');
  }

  function stopOpenRedirectSpider(win) {
    if (openredirectSpiderProcess) {
      openredirectSpiderProcess.send({ type: 'stop' });
      openredirectSpiderProcess.kill();
      openredirectSpiderProcess = null;
      win.webContents.send('openredirect-spider:status', 'Stopped');
    }
  }

  ipcMain.on('openredirect-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopOpenRedirectSpider(win); // Always stop any previous process before starting a new one
    startOpenRedirectSpider(win, opts);
  });
  ipcMain.on('openredirect-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopOpenRedirectSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (openredirectSpiderProcess) {
        openredirectSpiderProcess.kill();
        openredirectSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone CSRF Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the spiders/csrfSpider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let csrfSpiderProcess = null;

  function startCsrfSpider(win, opts) {
    if (csrfSpiderProcess) {
      win.webContents.send('csrf-spider:log', 'CSRF Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'spiders', 'csrfSpider.js');
    csrfSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    csrfSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`csrf-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    csrfSpiderProcess.on('exit', () => { csrfSpiderProcess = null; });
    csrfSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('csrf-spider:status', 'Running');
  }

  function stopCsrfSpider(win) {
    if (csrfSpiderProcess) {
      csrfSpiderProcess.send({ type: 'stop' });
      csrfSpiderProcess.kill();
      csrfSpiderProcess = null;
      win.webContents.send('csrf-spider:status', 'Stopped');
    }
  }

  ipcMain.on('csrf-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopCsrfSpider(win); // Always stop any previous process before starting a new one
    startCsrfSpider(win, opts);
  });
  ipcMain.on('csrf-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopCsrfSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (csrfSpiderProcess) {
        csrfSpiderProcess.kill();
        csrfSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone Clickjacking Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the clickjackingSpider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let clickjackingSpiderProcess = null;

  function startClickjackingSpider(win, opts) {
    if (clickjackingSpiderProcess) {
      win.webContents.send('clickjacking-spider:log', 'Clickjacking Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'clickjackingSpider.js');
    clickjackingSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    clickjackingSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`clickjacking-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    clickjackingSpiderProcess.on('exit', () => { clickjackingSpiderProcess = null; });
    clickjackingSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('clickjacking-spider:status', 'Running');
  }

  function stopClickjackingSpider(win) {
    if (clickjackingSpiderProcess) {
      clickjackingSpiderProcess.send({ type: 'stop' });
      clickjackingSpiderProcess.kill();
      clickjackingSpiderProcess = null;
      win.webContents.send('clickjacking-spider:status', 'Stopped');
    }
  }

  ipcMain.on('clickjacking-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopClickjackingSpider(win); // Always stop any previous process before starting a new one
    startClickjackingSpider(win, opts);
  });
  ipcMain.on('clickjacking-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopClickjackingSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (clickjackingSpiderProcess) {
        clickjackingSpiderProcess.kill();
        clickjackingSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone CORS Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the corsSpider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let corsSpiderProcess = null;

  function startCorsSpider(win, opts) {
    if (corsSpiderProcess) {
      win.webContents.send('cors-spider:log', 'CORS Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'corsSpider.js');
    corsSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    corsSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`cors-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    corsSpiderProcess.on('exit', () => { corsSpiderProcess = null; });
    corsSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('cors-spider:status', 'Running');
  }

  function stopCorsSpider(win) {
    if (corsSpiderProcess) {
      corsSpiderProcess.send({ type: 'stop' });
      corsSpiderProcess.kill();
      corsSpiderProcess = null;
      win.webContents.send('cors-spider:status', 'Stopped');
    }
  }

  ipcMain.on('cors-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopCorsSpider(win); // Always stop any previous process before starting a new one
    startCorsSpider(win, opts);
  });
  ipcMain.on('cors-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopCorsSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (corsSpiderProcess) {
        corsSpiderProcess.kill();
        corsSpiderProcess = null;
      }
    });
  }
})();

/**
 * ================================================================
 * Standalone Subdomain Takeover Spider IPC Handlers (Add to end of main.js)
 * ================================================================
 * Handles IPC between the Spiders UI and the subdomainTakeoverSpider.js engine.
 */
;(() => {
  const { fork } = require('child_process');
  const path = require('path');
  let subdomainSpiderProcess = null;

  function startSubdomainSpider(win, opts) {
    if (subdomainSpiderProcess) {
      win.webContents.send('subdomain-spider:log', 'Subdomain Takeover Spider already running.', 'warning');
      return;
    }
    const scriptPath = path.join(__dirname, 'subdomainTakeoverSpider.js');
    subdomainSpiderProcess = fork(scriptPath, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    subdomainSpiderProcess.on('message', (msg) => {
      if (!win || win.isDestroyed()) return;
      if (msg && msg.type) {
        win.webContents.send(`subdomain-spider:${msg.type}`, msg.data, msg.extra);
      }
    });
    subdomainSpiderProcess.on('exit', () => { subdomainSpiderProcess = null; });
    subdomainSpiderProcess.send({ type: 'start', data: opts });
    win.webContents.send('subdomain-spider:status', 'Running');
  }

  function stopSubdomainSpider(win) {
    if (subdomainSpiderProcess) {
      subdomainSpiderProcess.send({ type: 'stop' });
      subdomainSpiderProcess.kill();
      subdomainSpiderProcess = null;
      win.webContents.send('subdomain-spider:status', 'Stopped');
    }
  }

  ipcMain.on('subdomain-spider:start', (event, opts) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopSubdomainSpider(win); // Always stop any previous process before starting a new one
    startSubdomainSpider(win, opts);
  });
  ipcMain.on('subdomain-spider:stop', (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    stopSubdomainSpider(win);
  });

  if (spidersWindow) {
    spidersWindow.on('closed', () => {
      if (subdomainSpiderProcess) {
        subdomainSpiderProcess.kill();
        subdomainSpiderProcess = null;
      }
    });
  }
})();

// --- Open DevTools for a webview by webContentsId ---
ipcMain.on('open-webview-devtools', (event, webContentsId) => {
  try {
    if (!webContentsId) return;
    const wc = webContents.fromId(webContentsId);
    if (wc && !wc.isDestroyed()) {
      wc.openDevTools({ mode: 'detach' });
    }
  } catch (e) {
    console.error('[DevTools] Failed to open DevTools for webview:', e);
  }
});




















































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































