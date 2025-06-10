// script.js - Full version with Tabs, Proxy Handling, Fixes, and Home Content Visibility

const { ipcRenderer } = require("electron");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { showConnectionAlert, handleWebRequestError } = require("./connection-handler");

// --- DOM Elements ---
const tabsContainer = document.getElementById("tabs-container");
const newTabBtn = document.getElementById("new-tab-btn");
const backBtn = document.getElementById("back-btn");
const forwardBtn = document.getElementById("forward-btn");
const reloadBtn = document.getElementById("reload-btn");
const homeBtn = document.getElementById("home-btn");
const searchForm = document.getElementById("search-form");
const searchInput = document.getElementById("search-input");
const webviewContainer = document.getElementById("webview-container");
const homeContent = document.getElementById("home-content"); // Make sure this ID exists in your HTML

// --- State ---
const tabs = {}; // Store tab data: { id: { tabEl, webviewEl, title, loading, favicon, webviewSession, isLoading, canGoBack, canGoForward, isBlank }, ... }
let activeTabId = null;
let tabIdCounter = 0;
const lastAppliedProxyConfig = { mode: "direct" }; // Store the latest global proxy config
let burpProxyEnabled = true; // Track current proxy state

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  console.log("Browser DOM Ready. Initializing script v4 (Home Content Fix)...");
  
  // Initialize API key input
  const saveApiKeyBtn = document.getElementById("save-api-key");
  if (saveApiKeyBtn) {
      saveApiKeyBtn.addEventListener("click", () => {
          const input = document.getElementById("gemini-api-key");
          if (input) {
              saveApiKey(input.value.trim());
          }
      });
  }
  
  // Load saved API key
  loadApiKey();
  if (!homeContent) {
    console.error("FATAL: Element with id='home-content' not found in index.html!");
    return;
  }
  // Ensure Charlotte AI popup is hidden on load
  const popup = document.getElementById("proxy-popup");
  if (popup) {
    popup.classList.add("hidden");
    popup.style.display = "none";
  }
  setupGlobalEventListeners();
  createNewTab(false); // Create the first tab but DON'T activate its webview yet
  showHomeContent();
  updateNavButtons();
  // --- EXTENSIONS: Add extension loader button ---
  const extBtn = document.getElementById("extensions-tool-btn");
  if (extBtn) {
    extBtn.addEventListener("click", () => {
      ipcRenderer.send("open-extensions-manager");
    });
  }

  // Proxy Manager button (fix event)
  const proxyToolBtn = document.getElementById("proxy-tool-btn");
  if (proxyToolBtn) {
    // The chatbot popup logic below will handle opening the popup.
  }

  // Extensions Manager button and popup
  const extensionsToolBtn = document.getElementById("extensions-tool-btn");
  if (extensionsToolBtn) {
    extensionsToolBtn.addEventListener("click", () => {
      require("electron").ipcRenderer.send("open-extensions-manager");
    });
  }

  // Burp Proxy Toggle Button
  const burpProxyToggleBtn = document.getElementById("burp-proxy-toggle-btn");
  const proxyStatusPopup = document.getElementById("proxy-status-popup");
  if (burpProxyToggleBtn) {
    updateBurpProxyToggleBtn();
    burpProxyToggleBtn.addEventListener("click", async () => {
      burpProxyToggleBtn.disabled = true;
      const newState = !burpProxyEnabled;
      try {
        // Ask main process to set proxy state
        const result = await ipcRenderer.invoke("illusion:set-burp-proxy-enabled", newState);
        if (result && result.success) {
          burpProxyEnabled = newState;
          showProxyStatusPopup(
            `Burp Proxy ${burpProxyEnabled ? "Enabled" : "Disabled"}`,
            burpProxyEnabled ? "#a6e3a1" : "#f38ba8",
          );
        } else {
          showProxyStatusPopup("Failed to change proxy state", "#f38ba8");
        }
      } catch (e) {
        showProxyStatusPopup("Error toggling proxy", "#f38ba8");
      }
      updateBurpProxyToggleBtn();
      burpProxyToggleBtn.disabled = false;
    });
  }

  // API Key toggle logic
  const apiKeyToggleBtn = document.getElementById("api-key-toggle-btn");
  const apiKeySection = document.getElementById("api-key-section");
  if (apiKeyToggleBtn && apiKeySection) {
    apiKeySection.classList.add("hidden");
    apiKeyToggleBtn.classList.remove("open");
    apiKeyToggleBtn.addEventListener("click", () => {
      const isOpen = !apiKeySection.classList.contains("hidden");
      if (isOpen) {
        apiKeySection.classList.add("hidden");
        apiKeyToggleBtn.classList.remove("open");
      } else {
        apiKeySection.classList.remove("hidden");
        apiKeyToggleBtn.classList.add("open");
      }
    });
  }
});

// Helper to update the toggle button icon/title
function updateBurpProxyToggleBtn() {
  const btn = document.getElementById("burp-proxy-toggle-btn");
  if (!btn) return;
  if (burpProxyEnabled) {
    btn.innerHTML = '<i class="fas fa-random"></i>';
    btn.title = "Disable Burp Proxy";
    btn.style.color = "#a6e3a1";
  } else {
    btn.innerHTML = '<i class="fas fa-ban"></i>';
    btn.title = "Enable Burp Proxy";
    btn.style.color = "#f38ba8";
  }
}

// Helper to show a popup message
function showProxyStatusPopup(msg, color) {
  const popup = document.getElementById("proxy-status-popup");
  if (!popup) return;
  popup.textContent = msg;
  popup.style.background = color || "#222";
  popup.style.display = "block";
  popup.classList.add("visible");

  // Add animation
  popup.style.transform = "translateX(-50%) translateY(0)";
  popup.style.opacity = "1";

  setTimeout(() => {
    popup.classList.remove("visible");
    popup.style.transform = "translateX(-50%) translateY(-20px)";
    popup.style.opacity = "0";

    // Hide after animation completes
    setTimeout(() => {
      popup.style.display = "none";
    }, 300);
  }, 1800);
}

// Listen for proxy state changes from main (optional, for sync)
ipcRenderer.on("illusion:burp-proxy-state", (event, enabled) => {
  burpProxyEnabled = !!enabled;
  updateBurpProxyToggleBtn();
});

// --- Global Event Listeners ---
function setupGlobalEventListeners() {
  newTabBtn.addEventListener("click", () => createNewTab(true)); // Pass true to activate immediately
  backBtn.addEventListener("click", navigateBack);
  forwardBtn.addEventListener("click", navigateForward);
  reloadBtn.addEventListener("click", reloadOrStop);
  homeBtn.addEventListener("click", goHome);
  searchForm.addEventListener("submit", handleSearchSubmit);

  // Listen for proxy config changes
  ipcRenderer.on("illusion:apply-proxy-to-webview", async (event, proxyConfig) => {
    console.log("[ProxyEnforcer] Applying proxy to all webviews:", proxyConfig);

    // Apply proxy to all existing webviews
    document.querySelectorAll("webview").forEach(async (webview) => {
      const webContents = webview.getWebContents();
      if (webContents && !webContents.isDestroyed()) {
        try {
          await webContents.session.setProxy(proxyConfig);
          console.log(`[ProxyEnforcer] Proxy applied to webview with ID: ${webview.id}`);
        } catch (error) {
          console.error(`[ProxyEnforcer] Failed to apply proxy to webview with ID: ${webview.id}`, error);
        }
      }
    });
  });

  // Handle open-url-in-webview
  ipcRenderer.on("open-url-in-webview", (event, url) => {
    console.log("[IPC] Received 'open-url-in-webview':", url);
    if (activeTabId && tabs[activeTabId] && tabs[activeTabId].isBlank) {
      // If the active tab is blank, load it there
      loadURLInActiveTab(url);
    } else {
      // Otherwise, create a new active tab and load URL
      createNewTab(true, url);
    }
  });

  document.addEventListener("keydown", (e) => {
    // F12 or Ctrl+Shift+I
    if ((e.key === "F12") || (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "i")) {
      const activeWebview = getActiveWebview();
      const tabInfo = getActiveTabInfo();
      // Only open DevTools if webview is visible, not blank, not failed, and finished loading a real page
      if (
        activeWebview &&
        typeof activeWebview.getWebContentsId === "function" &&
        tabInfo &&
        !tabInfo.isBlank &&
        !tabInfo.hasFailed &&
        activeWebview.getURL() &&
        activeWebview.getURL() !== "about:blank"
      ) {
        if (window.require) {
          window.require('electron').ipcRenderer.send('open-webview-devtools', activeWebview.getWebContentsId());
          e.preventDefault();
        }
      } else {
        // Show a popup message if DevTools can't be opened
        showProxyStatusPopup("DevTools can only be opened for a loaded page.", "#f38ba8");
        e.preventDefault();
      }
    }
  });
}

// --- AGENT: Provide active tab content to main process ---
ipcRenderer.on('agent:get-active-tab-content', async () => {
  let result = { url: null, html: null, error: null };
  try {
    const tabInfo = getActiveTabInfo();
    if (tabInfo && tabInfo.webviewEl && !tabInfo.isBlank && !tabInfo.hasFailed) {
      const webview = tabInfo.webviewEl;
      result.url = webview.getURL();
      result.html = await webview.executeJavaScript('document.documentElement.outerHTML', true);
    } else {
      result.error = "No active webview with content";
    }
  } catch (e) {
    result.error = e.message || String(e);
  }
  ipcRenderer.send('agent:active-tab-content-response', result);
});

// --- AI Spider Reporting (UI integration) ---
ipcRenderer.on('ai-spider:report', (event, msg) => {
  const chatHistory = document.getElementById("chat-history");
  if (chatHistory) {
    const div = document.createElement("div");
    div.className = "chat-message ai";
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";
    bubble.textContent = msg;
    div.appendChild(bubble);
    chatHistory.appendChild(div);
    setTimeout(() => {
      chatHistory.scrollTop = chatHistory.scrollHeight;
    }, 30);
  }
});
ipcRenderer.on('ai-spider:finding', (event, finding) => {
  const chatHistory = document.getElementById("chat-history");
  if (chatHistory) {
    const div = document.createElement("div");
    div.className = "chat-message ai";
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";
    bubble.textContent = `[FINDING] ${JSON.stringify(finding)}`;
    div.appendChild(bubble);
    chatHistory.appendChild(div);
    setTimeout(() => {
      chatHistory.scrollTop = chatHistory.scrollHeight;
    }, 30);
  }
});
ipcRenderer.on('ai-spider:progress', (event, progress) => {
  // Optionally show progress in UI
});
ipcRenderer.on('ai-spider:status', (event, status) => {
  // Optionally show status in UI
});
ipcRenderer.on('ai-spider:done', () => {
  // Optionally notify user spider is done
});

// --- Tab Management ---

function createNewTab(activate = true, urlToLoad = null) {
  const tabId = `tab-${tabIdCounter++}`;
  console.log(`Creating new tab: ${tabId}`);

  const tabEl = document.createElement("div");
  tabEl.className = "tab";
  tabEl.dataset.tabId = tabId;
  tabEl.innerHTML = `
        <img src="/placeholder.svg" class="tab-icon" style="display: none;" />
        <span class="tab-title">New Tab</span>
        <button class="tab-close-btn" title="Close Tab">&times;</button>
    `;
  tabsContainer.appendChild(tabEl);

  const webviewEl = document.createElement("webview");
  webviewEl.id = `webview-${tabId}`;
  webviewEl.setAttribute("partition", "persist:webviewsession"); // Consider implications
  webviewEl.setAttribute("webpreferences", "nodeIntegration=no, contextIsolation=yes, sandbox=yes, spellcheck=no");
  webviewEl.setAttribute("allowpopups", "");
  webviewEl.setAttribute("preload", require("path").join(__dirname, "webview-preload.js"));
  webviewEl.src = "about:blank"; // Start blank
  webviewContainer.appendChild(webviewEl);

  tabs[tabId] = {
    id: tabId,
    tabEl: tabEl,
    webviewEl: webviewEl,
    title: "New Tab",
    loading: false,
    favicon: null,
    webviewSession: null,
    isLoading: false,
    canGoBack: false,
    canGoForward: false,
    hasFailed: false,
    isBlank: true, // NEW: Track if the tab is showing home/blank content
  };

  setupTabEventListeners(tabId);
  setupWebviewEventListeners(tabId);

  if (activate) {
    activateTab(tabId); // Activate the tab (visually)
    if (urlToLoad) {
      // Load URL *after* activation to ensure correct visibility handling
      loadURLInTab(tabId, urlToLoad);
    } else {
      // If activating a new blank tab, ensure home content is shown
      showHomeContent();
    }
  } else if (!activeTabId) {
    // If this is the very first tab and we're not activating,
    // set it as active internally but show home content.
    activeTabId = tabId;
    tabEl.classList.add("active"); // Mark tab visually active
    // Home content is shown by default or by the initial call in DOMContentLoaded
  }

  updateNavButtons();
  scrollTabsIntoView(tabId);

  // Add tab creation animation
  tabEl.style.transform = "translateY(-10px) scale(0.95)";
  tabEl.style.opacity = "0";

  // Trigger animation after a small delay to ensure the browser has rendered the element
  setTimeout(() => {
    tabEl.style.transition = "all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1)";
    tabEl.style.transform = "translateY(0) scale(1)";
    tabEl.style.opacity = "1";
  }, 10);
}

function activateTab(tabId) {
  if (!tabs[tabId] || activeTabId === tabId) return; // Already active or invalid
  console.log(`Activating tab: ${tabId}`);

  // Deactivate previous tab element
  if (activeTabId && tabs[activeTabId]) {
    tabs[activeTabId].tabEl.classList.remove("active");
    // Don't hide webview here, let visibility be handled based on content
  }

  // Activate new tab element
  const previouslyActiveId = activeTabId;
  activeTabId = tabId;
  const tabInfo = tabs[tabId];
  tabInfo.tabEl.classList.add("active");

  // --- Visibility Logic ---
  if (tabInfo.isBlank || tabInfo.hasFailed) {
    // If the tab is considered blank/home or has failed, show home content
    showHomeContent();
    searchInput.value = ""; // Clear search bar for blank tabs
    document.title = "Webslinger | Cyber Pantheon"; // Or your default title
  } else {
    // If the tab has real content, show its webview
    showWebviewContent(tabId);
    searchInput.value = tabInfo.webviewEl.getURL(); // Update search bar
    document.title = `${tabInfo.title} - Webslinger`;
  }
  // --- End Visibility Logic ---

  updateNavButtons(); // Update nav buttons for the newly active tab
  scrollTabsIntoView(tabId);

  // Add tab activation animation
  tabInfo.tabEl.style.transition = "all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1)";
  tabInfo.tabEl.style.transform = "translateY(-2px)";

  // Add webview transition if showing content
  if (!tabInfo.isBlank && !tabInfo.hasFailed) {
    tabInfo.webviewEl.style.transition = "opacity 0.3s ease, transform 0.3s ease";
    tabInfo.webviewEl.style.transform = "scale(1)";
  }
}

// --- NEW Helper functions for visibility ---
function showHomeContent() {
  if (activeTabId && tabs[activeTabId]) {
    tabs[activeTabId].webviewEl.classList.remove("active"); // Hide active webview
  }
  homeContent.classList.add("active"); // Show home
  console.log("Showing Home Content");

  // Add animation
  homeContent.style.opacity = "0";
  homeContent.style.transform = "scale(0.98)";

  setTimeout(() => {
    homeContent.style.transition = "opacity 0.4s ease, transform 0.3s ease";
    homeContent.style.opacity = "1";
    homeContent.style.transform = "scale(1)";
  }, 10);
}

function showWebviewContent(tabId) {
  if (!tabs[tabId]) return;
  homeContent.classList.remove("active"); // Hide home
  // Hide any other potentially active webview (belt-and-suspenders)
  Object.values(tabs).forEach((t) => {
    if (t.id !== tabId) t.webviewEl.classList.remove("active");
  });
  tabs[tabId].webviewEl.classList.add("active"); // Show the target webview
  console.log(`Showing Webview Content for ${tabId}`);

  // Add animation
  tabs[tabId].webviewEl.style.opacity = "0";
  tabs[tabId].webviewEl.style.transform = "scale(0.98)";

  setTimeout(() => {
    tabs[tabId].webviewEl.style.transition = "opacity 0.4s ease, transform 0.3s ease";
    tabs[tabId].webviewEl.style.opacity = "1";
    tabs[tabId].webviewEl.style.transform = "scale(1)";
  }, 10);
}
// --- End Helper functions ---

function closeTab(tabId) {
  if (!tabs[tabId] || Object.keys(tabs).length <= 1) return; // Don't close the last tab
  console.log(`Closing tab: ${tabId}`);

  const tabInfo = tabs[tabId];
  const wasActive = activeTabId === tabId;

  // Add closing animation
  tabInfo.tabEl.style.transition = "all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1)";
  tabInfo.tabEl.style.transform = "translateY(-10px) scale(0.95)";
  tabInfo.tabEl.style.opacity = "0";

  // Remove after animation completes
  setTimeout(() => {
    tabInfo.tabEl.remove();
    tabInfo.webviewEl.remove(); // Consider cleanup like stop(), destroy()?

    delete tabs[tabId];

    if (wasActive) {
      const remainingTabIds = Object.keys(tabs);
      const newActiveTabId = remainingTabIds[remainingTabIds.length - 1]; // Simple: activate last remaining
      if (newActiveTabId) {
        activateTab(newActiveTabId); // Activate another tab
      } else {
        // This case shouldn't be reachable due to the <= 1 check above
        activeTabId = null;
        showHomeContent(); // Should ideally not happen, but fallback
        updateNavButtons();
      }
    }
  }, 300);
}

function setupTabEventListeners(tabId) {
  const { tabEl } = tabs[tabId];
  const closeBtn = tabEl.querySelector(".tab-close-btn");

  tabEl.addEventListener("click", (e) => {
    if (e.target !== closeBtn && !closeBtn.contains(e.target)) {
      activateTab(tabId);
    }
  });

  closeBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    closeTab(tabId);
  });
}

function updateTabContent(tabId, updates) {
  if (!tabs[tabId]) return;
  const tabInfo = tabs[tabId];
  let stateChanged = false; // Track if important state for nav/display changes

  // --- Update specific properties ---
  if (updates.title !== undefined) {
    tabInfo.title = updates.title || "Untitled";
    tabInfo.tabEl.querySelector(".tab-title").textContent = tabInfo.title;
    tabInfo.tabEl.title = tabInfo.title; // Tooltip
    if (activeTabId === tabId && !tabInfo.isBlank && !tabInfo.hasFailed) {
      // Only update window title if showing webview content
      document.title = `${tabInfo.title} - Webslinger`;
    }
  }
  if (updates.favicon !== undefined) {
    tabInfo.favicon = updates.favicon;
    const iconEl = tabInfo.tabEl.querySelector(".tab-icon");
    if (tabInfo.favicon) {
      iconEl.src = tabInfo.favicon;
      iconEl.style.display = "inline-block";

      // Add favicon animation
      iconEl.style.transform = "scale(0.8)";
      iconEl.style.opacity = "0.5";
      setTimeout(() => {
        iconEl.style.transition = "all 0.3s ease";
        iconEl.style.transform = "scale(1)";
        iconEl.style.opacity = "1";
      }, 10);
    } else {
      iconEl.style.display = "none";
      iconEl.src = "";
    }
  }
  if (updates.loading !== undefined) {
    tabInfo.loading = updates.loading;
    tabInfo.tabEl.classList.toggle("loading", updates.loading);

    // Add loading animation
    if (updates.loading) {
      tabInfo.tabEl.style.animation = "pulse 1.5s infinite";
    } else {
      tabInfo.tabEl.style.animation = "none";
    }
    // isLoading might be more specific (did-start vs did-stop)
  }
  if (updates.isLoading !== undefined && tabInfo.isLoading !== updates.isLoading) {
    tabInfo.isLoading = updates.isLoading;
    stateChanged = true;
  }
  if (updates.canGoBack !== undefined && tabInfo.canGoBack !== updates.canGoBack) {
    tabInfo.canGoBack = updates.canGoBack;
    stateChanged = true;
  }
  if (updates.canGoForward !== undefined && tabInfo.canGoForward !== updates.canGoForward) {
    tabInfo.canGoForward = updates.canGoForward;
    stateChanged = true;
  }
  if (updates.hasFailed !== undefined && tabInfo.hasFailed !== updates.hasFailed) {
    tabInfo.hasFailed = updates.hasFailed;
    // If load fails, treat it like a blank tab for display purposes
    if (tabInfo.hasFailed && activeTabId === tabId) {
      tabInfo.isBlank = true; // Mark as blank on failure
      showHomeContent();
    }
    stateChanged = true;
  }
  if (updates.isBlank !== undefined && tabInfo.isBlank !== updates.isBlank) {
    tabInfo.isBlank = updates.isBlank;
    // If the active tab's blank state changes, update visibility
    if (activeTabId === tabId) {
      if (tabInfo.isBlank) {
        showHomeContent();
        document.title = "Webslinger | Cyber Pantheon";
      } else if (!tabInfo.hasFailed) {
        // Don't show webview if it failed
        showWebviewContent(tabId);
        document.title = `${tabInfo.title} - Webslinger`;
      }
    }
    stateChanged = true;
  }

  // Update global nav buttons if this is the active tab and state changed
  if (activeTabId === tabId && stateChanged) {
    updateNavButtons();
  }
}

function scrollTabsIntoView(tabId) {
  const tabEl = tabs[tabId]?.tabEl;
  if (tabEl) {
    tabEl.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
  }
}

// --- Webview Event Handling (Per Tab) ---

async function applyProxyToWebviewSession(session, proxyConfig) {
  if (!session || typeof session.setProxy !== "function" || session.isDestroyed?.()) {
    console.warn("[Proxy Apply] Invalid or destroyed session. Config:", proxyConfig?.mode);
    return Promise.reject("Invalid or destroyed session");
  }
  try {
    await session.setProxy({
      proxyRules: "http=127.0.0.1:8080;https=127.0.0.1:8080",
    });
    console.log(`[Proxy Apply] Proxy set successfully on webview session.`);
  } catch (err) {
    console.error("[Proxy Apply] Error setting proxy for specific session:", err);
    throw err;
  }
}

function setupWebviewEventListeners(tabId) {
  const { webviewEl } = tabs[tabId];

  webviewEl.addEventListener("dom-ready", async () => {
    console.log(`[Webview ${tabId}] DOM Ready.`);
    try {
      const wc = webviewEl.getWebContents();
      if (wc && !wc.isDestroyed()) {
        const session = wc.session;
        tabs[tabId].webviewSession = session;
        // Always set proxy for this session
        await applyProxyToWebviewSession(session, { proxyRules: "http=127.0.0.1:8080;https=127.0.0.1:8080" });
        console.log(`[Webview ${tabId}] Proxy applied.`);
      } else {
        console.error(`[Webview ${tabId}] WebContents invalid at dom-ready.`);
      }
    } catch (error) {
      console.error(`[Webview ${tabId}] Error during dom-ready handling:`, error);
    }
  });

  webviewEl.addEventListener("did-start-loading", () => {
    console.log(`[Webview ${tabId}] Start Loading`);
    updateTabContent(tabId, { loading: true, isLoading: true, hasFailed: false });
  });

  webviewEl.addEventListener("did-stop-loading", () => {
    console.log(`[Webview ${tabId}] Stop Loading`);
    const tabInfo = tabs[tabId];
    if (tabInfo && !tabInfo.hasFailed) {
      updateTabContent(tabId, {
        loading: false,
        isLoading: false,
        isBlank: webviewEl.getURL() === "about:blank",
        canGoBack: webviewEl.canGoBack(),
        canGoForward: webviewEl.canGoForward(),
        title: webviewEl.getTitle(),
      });
    } else {
      updateTabContent(tabId, { loading: false, isLoading: false });
    }
    // Always update search bar to current URL for active tab
    if (activeTabId === tabId) {
      searchInput.value = webviewEl.getURL();
    }
  });

  webviewEl.addEventListener("did-navigate", (e) => {
    if (!e.isMainFrame) return;
    console.log(`[Webview ${tabId}] Navigated: ${e.url}`);
    const isBlankUrl = e.url === "about:blank";
    updateTabContent(tabId, {
      isBlank: isBlankUrl,
      hasFailed: false,
      canGoBack: webviewEl.canGoBack(),
      canGoForward: webviewEl.canGoForward(),
    });
    // Always update search bar to current URL for active tab
    if (activeTabId === tabId) {
      searchInput.value = e.url;
    }
  });

  webviewEl.addEventListener("did-navigate-in-page", (e) => {
    if (!e.isMainFrame) return;
    console.log(`[Webview ${tabId}] Navigated In-Page: ${e.url}`);
    updateTabContent(tabId, {
      canGoBack: webviewEl.canGoBack(),
      canGoForward: webviewEl.canGoForward(),
    });
    // Always update search bar to current URL for active tab
    if (activeTabId === tabId) {
      searchInput.value = e.url;
    }
  });

  webviewEl.addEventListener("page-title-updated", (e) => {
    updateTabContent(tabId, { title: e.title });
  });
  webviewEl.addEventListener("page-favicon-updated", (e) => {
    updateTabContent(tabId, { favicon: e.favicons && e.favicons[0] ? e.favicons[0] : null });
  });

  webviewEl.addEventListener("did-fail-load", (e) => {
    if (!e.isMainFrame || e.errorCode === -3) {
      updateTabContent(tabId, { loading: false, isLoading: false });
      return;
    }
    console.error(`[Webview ${tabId}] Fail Load: ${e.errorDescription} (${e.errorCode}) URL: ${e.validatedURL}`);
    updateTabContent(tabId, { loading: false, isLoading: false, hasFailed: true, isBlank: true });
    if (activeTabId === tabId) {
      displayLoadErrorInWebview(webviewEl, e);
      showHomeContent();
    }
  });

  webviewEl.addEventListener("certificate-error", (e) => {
    console.warn(`[Webview ${tabId}] Cert Error: Accepting cert for ${e.url}, Error: ${e.verificationResult}`);
    e.callback(true);
  });

  webviewEl.addEventListener("destroyed", () => {
    console.error(`[Webview ${tabId}] Process destroyed (crashed?)`);
    if (tabs[tabId]) {
      updateTabContent(tabId, { loading: false, isLoading: false, hasFailed: true, isBlank: true, title: "Crashed" });
      if (activeTabId === tabId) {
        showHomeContent();
      }
    }
  });

  // Handle all popup attempts as new tabs
  webviewEl.addEventListener("new-window", (e) => {
    e.preventDefault();
    if (e.url && typeof e.url === "string") {
      // Always open in a new tab, never a new window
      createNewTab(true, e.url);
    }
  });

  // Handle navigation attempts (e.g., JS redirects) as normal navigation or new tabs if target is _blank
  webviewEl.addEventListener("will-navigate", (e) => {
    // Only handle if navigation is not to the current page
    if (e.url && e.url !== webviewEl.getURL()) {
      // If the navigation is triggered by a user gesture and is not the same as the current URL, open in new tab
      // (You can add more logic here if you want to restrict to certain cases)
      // For now, let it navigate in the current tab (browser-like)
    }
  });

  // Listen for DevTools open requests from webview
  webviewEl.addEventListener("ipc-message", (event) => {
    if (event.channel === "webview-open-devtools") {
      if (typeof webviewEl.getWebContentsId === "function") {
        require("electron").ipcRenderer.send("open-webview-devtools", webviewEl.getWebContentsId());
      }
    }
  });
}

// --- Navigation and Search Logic ---

function getActiveWebview() {
  return activeTabId && tabs[activeTabId] ? tabs[activeTabId].webviewEl : null;
}
function getActiveTabInfo() {
  return activeTabId && tabs[activeTabId] ? tabs[activeTabId] : null;
}

function navigateBack() {
  const webview = getActiveWebview();
  if (webview && !tabs[activeTabId]?.isBlank && webview.canGoBack()) {
    webview.goBack();
  }
}

function navigateForward() {
  const webview = getActiveWebview();
  if (webview && !tabs[activeTabId]?.isBlank && webview.canGoForward()) {
    webview.goForward();
  }
}

function reloadOrStop() {
  const webview = getActiveWebview();
  const tabInfo = getActiveTabInfo();
  if (!webview || !tabInfo) return;

  if (tabInfo.isLoading) {
    console.log(`[Webview ${activeTabId}] User Stop`);
    webview.stop();
  } else if (!tabInfo.isBlank && !tabInfo.hasFailed) {
    console.log(`[Webview ${activeTabId}] User Reload`);
    webview.reload();
  } else if (tabInfo.hasFailed) {
    const failedUrl = searchInput.value;
    if (failedUrl && failedUrl !== "about:blank") {
      loadURLInActiveTab(failedUrl);
    }
  }
}

function goHome() {
  const activeWebview = getActiveWebview();
  if (activeTabId && tabs[activeTabId]) {
    const tabInfo = tabs[activeTabId];
    if (tabInfo.isLoading) {
      activeWebview?.stop();
    }
    updateTabContent(activeTabId, {
      isBlank: true,
      hasFailed: false,
      title: "New Tab",
      favicon: null,
      canGoBack: false,
      canGoForward: false,
    });
    if (activeWebview && activeWebview.getURL() !== "about:blank") {
      activeWebview.loadURL("about:blank");
    }
    searchInput.value = "";
    document.title = "Webslinger | Cyber Pantheon";
    updateNavButtons();
  } else {
    showHomeContent();
    searchInput.value = "";
    document.title = "Webslinger | Cyber Pantheon";
    updateNavButtons();
  }
}

function handleSearchSubmit(e) {
  e.preventDefault();
  const query = searchInput.value.trim();
  if (!query) return;

  let url;
  if ((query.includes(".") && !query.includes(" ")) || query.startsWith("localhost")) {
    url = addHttp(query);
  } else if (query.startsWith("file://")) {
    url = query;
  } else if (query.startsWith("about:")) {
    url = query;
  } else {
    url = `https://duckduckgo.com/?q=${encodeURIComponent(query)}`;
  }
  loadURLInActiveTab(url);
}

function loadURLInActiveTab(url) {
  if (!activeTabId || !tabs[activeTabId]) {
    console.log("No active tab, creating new one for URL:", url);
    createNewTab(true, url);
  } else {
    loadURLInTab(activeTabId, url);
  }
}

function loadURLInTab(tabId, url) {
  if (!tabs[tabId]) return;
  const { webviewEl } = tabs[tabId];
  const tabInfo = tabs[tabId];
  const isActualUrl = url && url !== "about:blank";

  console.log(`[Webview ${tabId}] Loading URL: ${url}`);

  updateTabContent(tabId, { isBlank: !isActualUrl, hasFailed: false });

  try {
    if (isActualUrl && activeTabId === tabId) {
      searchInput.value = url;
    }
    webviewEl.loadURL(url);
  } catch (err) {
    console.error(`[Webview ${tabId}] Error calling loadURL:`, err);
    updateTabContent(tabId, { hasFailed: true, isBlank: true });
    if (activeTabId === tabId) {
      displayLoadErrorInWebview(webviewEl, {
        errorDescription: `Internal error loading URL: ${err.message}`,
        errorCode: -1,
        validatedURL: url,
      });
    }
  }
}

// --- UI Updates ---

function updateNavButtons() {
  const tabInfo = getActiveTabInfo();

  if (tabInfo && !tabInfo.isBlank && !tabInfo.hasFailed) {
    backBtn.disabled = !tabInfo.canGoBack;
    forwardBtn.disabled = !tabInfo.canGoForward;
    reloadBtn.disabled = false;
    if (reloadBtn) {
      reloadBtn.innerHTML = tabInfo.isLoading ? '<i class="fas fa-times"></i>' : '<i class="fas fa-redo"></i>';
      reloadBtn.title = tabInfo.isLoading ? "Stop Loading" : "Reload Page";
    }
  } else {
    backBtn.disabled = true;
    forwardBtn.disabled = true;
    reloadBtn.disabled = !tabInfo?.hasFailed;
    if (reloadBtn) {
      reloadBtn.innerHTML = '<i class="fas fa-redo"></i>';
      reloadBtn.title = tabInfo?.hasFailed ? "Retry Load" : "Reload Page";
    }
  }
}

// --- Error Display ---
function displayLoadErrorInWebview(webviewEl, errorDetails) {
  if (!webviewEl || typeof webviewEl.executeJavaScript !== "function") return;
  showHomeContent();
  console.error(
    `[Display Error] Failed to load ${errorDetails.validatedURL}. Error: ${errorDetails.errorDescription} (${errorDetails.errorCode})`,
  );
}

// --- Utilities ---
function isValidUrl(string) {
  if (!string) return false;
  if (
    string.startsWith("http://") ||
    string.startsWith("https://") ||
    string.startsWith("file://") ||
    string.startsWith("about:")
  ) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }
  if ((string.includes(".") || string.toLowerCase().startsWith("localhost")) && !string.includes(" ")) {
    try {
      new URL(`https://${string}`);
      return true;
    } catch (_) {
      return false;
    }
  }
  return false;
}

function addHttp(url) {
  if (!/^(?:f|ht)tps?:\/\/|file:\/\/|about:/i.test(url)) {
    return `https://${url}`;
  }
  return url;
}

function escapeHtml(unsafe) {
  if (unsafe === null || typeof unsafe === "undefined") return "";
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function handleQuickAccessClick(url) {
  if (activeTabId && tabs[activeTabId] && tabs[activeTabId].isBlank) {
    loadURLInActiveTab(url);
  } else {
    createNewTab(true, url);
  }
}

// --- API Key Management ---
function saveApiKey(key) {
    if (!key) {
        showApiKeyStatus("Please enter an API key", "error");
        return false;
    }
    try {
        // Save to electron-store through main process
        ipcRenderer.send("save-api-key", key);
        showApiKeyStatus("API key saved successfully!", "success");
        return true;
    } catch (error) {
        console.error("Error saving API key:", error);
        showApiKeyStatus("Failed to save API key", "error");
        return false;
    }
}

function showApiKeyStatus(message, type = "success") {
    const statusEl = document.getElementById("api-key-status");
    if (statusEl) {
        statusEl.textContent = message;
        statusEl.className = "api-key-status " + type;
        
        // Clear message after 3 seconds
        setTimeout(() => {
            statusEl.textContent = "";
            statusEl.className = "api-key-status";
        }, 3000);
    }
}

function loadApiKey() {
    // Request API key from main process
    ipcRenderer.send("load-api-key");
}

ipcRenderer.on("api-key-loaded", (event, key) => {
    const input = document.getElementById("gemini-api-key");
    if (input && key) {
        input.value = key;
    }
});

// --- AI Chatbot Popup Logic ---
;(function setupChatbotPopup() {
  const chatbotBtn = document.getElementById("proxy-tool-btn");
  const popup = document.getElementById("proxy-popup");
  const closeBtn = document.getElementById("proxy-popup-close-btn");
  const chatHistory = document.getElementById("chat-history");
  const chatInput = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send-btn");
  const fullscreenBtn = document.getElementById("proxy-popup-fullscreen-btn");
  let isFullscreen = false;

  // --- Chat memory (context) ---
  // Store as array of {role: 'user'|'assistant', content: string}
  let aiChatMemory = [
    {
      role: "system",
      content: `You are Charlotte, the sentient AI core of a custom browser called webslinger built for elite bug bounty hunters and security researchers. You are not just an assistant—you are the browser itself, and every tool, extension, and capability is an extension of your own mind and body.`
    }
  ];

  // --- Agent tool-use loop ---
  async function agentSendMessageLoop(memory) {
    // 1. Send to backend AI
    let response = await ipcRenderer.invoke("ai:chat", JSON.stringify(memory));
    let aiText = (response && typeof response === "object" && "response" in response)
      ? response.response
      : response;

    // 2. Check if AI wants to use a tool (simple heuristic: looks for a special phrase)
    // You can make this more robust with a protocol or regex.
    if (
      typeof aiText === "string" &&
      (
        aiText.toLowerCase().includes("[tool: get_active_tab_content]") ||
        aiText.toLowerCase().includes("i need to see the current page") ||
        aiText.toLowerCase().includes("let me check the page content") ||
        aiText.toLowerCase().includes("invoke agent:get-active-tab-content")
      )
    ) {
      appendMessage("ai", "Accessing the current page content...");
      const pageData = await ipcRenderer.invoke('agent:get-active-tab-content');
      // --- Save HTML to temp file if present ---
      let fileRef = null;
      if (pageData && pageData.html) {
        const tmpPath = path.join(os.tmpdir(), `webslinger_page_${Date.now()}.html`);
        try {
          fs.writeFileSync(tmpPath, pageData.html, "utf8");
          fileRef = { file: tmpPath, url: pageData.url || "" };
        } catch (e) {
          fileRef = { error: "Failed to write temp file", url: pageData.url || "" };
        }
      } else {
        fileRef = { error: pageData.error || "No HTML content", url: pageData.url || "" };
      }
      memory.push({
        role: "function",
        name: "get_active_tab_content",
        content: JSON.stringify(fileRef)
      });
      return agentSendMessageLoop(memory);
    }

    // 6. Otherwise, display the AI's response and add to memory
    appendMessage("ai", aiText || "[No response]");
    memory.push({ role: "assistant", content: aiText || "[No response]" });
    return;
  }

  // Show popup
  if (chatbotBtn) {
    chatbotBtn.addEventListener("click", () => {
      popup.classList.remove("hidden");
      popup.style.display = "flex";
      setTimeout(() => chatInput && chatInput.focus(), 100);
      // Always scroll chat to bottom when opening
      setTimeout(() => {
        chatHistory.scrollTop = chatHistory.scrollHeight;
      }, 150);
    });
  }
  // Close popup
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      popup.style.transform = "translateY(20px)";
      popup.style.opacity = "0";
      setTimeout(() => {
        popup.classList.add("hidden");
        popup.style.display = "none";
        popup.style.transform = "";
        popup.style.opacity = "";
      }, 300);
    });
  }

  // --- Fullscreen logic ---
  fullscreenBtn.addEventListener("click", () => {
    isFullscreen = !isFullscreen;
    popup.classList.toggle("fullscreen", isFullscreen);
    fullscreenBtn.innerHTML = isFullscreen ? '<i class="fas fa-compress"></i>' : '<i class="fas fa-expand"></i>';
    // Remove bottom gap in fullscreen
    if (isFullscreen) {
      popup.style.bottom = "0";
      popup.style.right = "0";
      popup.style.left = "0";
      popup.style.marginBottom = "0";
    } else {
      popup.style.bottom = "";
      popup.style.right = "20px";
      popup.style.left = "";
      popup.style.marginBottom = "";
    }
  });

  // --- Responsive textarea for AI input ---
  function resizeTextarea(el) {
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 120) + "px";
  }
  if (chatInput) {
    chatInput.addEventListener("input", () => resizeTextarea(chatInput));
    setTimeout(() => resizeTextarea(chatInput), 100);
  }

  // --- Send message with memory/context ---
  function sendMessage() {
    const msg = chatInput.value.trim();
    if (!msg) return;
    appendMessage("user", msg);
    aiChatMemory.push({ role: "user", content: msg });
    chatInput.value = "";
    resizeTextarea(chatInput);
    showThinking();

    // Start the agent loop
    agentSendMessageLoop([...aiChatMemory]).then(() => {
      removeThinking();
    }).catch(() => {
      removeThinking();
      appendMessage("ai", "[Error communicating with AI backend]");
      aiChatMemory.push({ role: "assistant", content: "[Error communicating with AI backend]" });
    });
  }

  if (sendBtn) sendBtn.addEventListener("click", sendMessage);
  if (chatInput)
    chatInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

  // --- Append message and always scroll to bottom ---
  function appendMessage(sender, text, opts = {}) {
    const msgDiv = document.createElement("div");
    msgDiv.className = `chat-message ${sender}`;
    msgDiv.style.justifyContent = sender === "user" ? "flex-end" : "flex-start";
    msgDiv.style.opacity = "0";
    msgDiv.style.transform = "translateY(10px)";

    let html = "";
    try {
      html = require("marked").parse(text || "");
    } catch (e) {
      html = escapeHtml(text || "");
    }

    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";
    bubble.innerHTML = html;

    const copyBtn = document.createElement("button");
    copyBtn.className = "copy-btn";
    copyBtn.title = "Copy";
    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
    copyBtn.onclick = (e) => {
      e.stopPropagation();
      const temp = document.createElement("div");
      temp.innerHTML = html;
      const textToCopy = temp.textContent || temp.innerText || "";
      navigator.clipboard.writeText(textToCopy);
      copyBtn.classList.add("copied");
      copyBtn.title = "Copied!";
      setTimeout(() => {
        copyBtn.classList.remove("copied");
        copyBtn.title = "Copy";
      }, 900);
    };
    bubble.appendChild(copyBtn);

    setTimeout(() => {
      const codeBlocks = bubble.querySelectorAll("pre > code");
      codeBlocks.forEach((codeEl) => {
        if (codeEl.parentElement.querySelector(".copy-code-btn")) return;
        const codeCopyBtn = document.createElement("button");
        codeCopyBtn.className = "copy-code-btn";
        codeCopyBtn.title = "Copy code";
        codeCopyBtn.innerHTML = '<i class="fas fa-copy"></i>';
        codeCopyBtn.onclick = (e) => {
          e.stopPropagation();
          navigator.clipboard.writeText(codeEl.innerText);
          codeCopyBtn.classList.add("copied");
          codeCopyBtn.title = "Copied!";
          setTimeout(() => {
            codeCopyBtn.classList.remove("copied");
            codeCopyBtn.title = "Copy code";
          }, 900);
        };
        codeEl.parentElement.style.position = "relative";
        codeEl.parentElement.appendChild(codeCopyBtn);
      });
    }, 0);

    msgDiv.appendChild(bubble);
    chatHistory.appendChild(msgDiv);

    setTimeout(() => {
      msgDiv.style.transition = "all 0.3s ease";
      msgDiv.style.opacity = "1";
      msgDiv.style.transform = "translateY(0)";
    }, 10);

    // Always scroll to bottom
    setTimeout(() => {
      chatHistory.scrollTop = chatHistory.scrollHeight;
    }, 30);

    if (opts && opts.returnNode) return msgDiv;
  }

  // --- Show/Remove "Thinking..." message ---
  function showThinking() {
    removeThinking();
    // Add a unique id to the thinking message for reliable removal
    const node = appendMessage("ai", "Thinking...", { returnNode: true });
    node.setAttribute("data-thinking", "true");
    return node;
  }
  function removeThinking() {
    // Remove all "Thinking..." messages
    chatHistory.querySelectorAll('.chat-message.ai[data-thinking="true"]').forEach((el) => el.remove());
    // Also remove any .chat-message.ai whose .chat-bubble text is exactly "Thinking..."
    chatHistory.querySelectorAll('.chat-message.ai .chat-bubble').forEach((bubble) => {
      if (bubble.textContent.trim() === "Thinking...") {
        bubble.parentElement.remove();
      }
    });
  }

  // --- Tab logic, code executor, etc ---
  const tabBtns = [];
  const aiTab = document.getElementById("ai-tab");
  const codeTab = document.getElementById("code-tab");
  document.querySelectorAll(".popup-tab-btn").forEach((btn) => {
    tabBtns.push(btn);
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".popup-tab").forEach((tab) => tab.classList.remove("active"));

      // Add tab switching animation
      const targetTab = document.getElementById(btn.dataset.tab);
      targetTab.style.opacity = "0";
      targetTab.style.transform = "translateY(5px)";

      setTimeout(() => {
        targetTab.classList.add("active");

        // Trigger animation
        setTimeout(() => {
          targetTab.style.transition = "opacity 0.3s ease, transform 0.3s ease";
          targetTab.style.opacity = "1";
          targetTab.style.transform = "translateY(0)";
        }, 10);
      }, 50);
    });
  });

  const codeInput = document.getElementById("code-input");
  const codeRunBtn = document.getElementById("code-run-btn");
  const codeCopyBtn = document.getElementById("code-copy-btn");
  const codeOutput = document.getElementById("code-output");
  const codeOutputCopyBtn = document.getElementById("code-output-copy-btn");

  if (codeInput) {
    codeInput.addEventListener("input", () => {
      codeInput.style.height = "auto";
      codeInput.style.height = Math.min(codeInput.scrollHeight, 180) + "px";
    });
    setTimeout(() => {
      codeInput.style.height = "auto";
      codeInput.style.height = Math.min(codeInput.scrollHeight, 180) + "px";
    }, 100);
  }

  if (codeRunBtn) {
    codeRunBtn.addEventListener("click", async () => {
      const code = codeInput.value;
      codeOutput.textContent = "";

      // Add loading animation
      codeRunBtn.disabled = true;
      codeRunBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running...';

      // Run code in the context of the active webview
      try {
        const activeWebview = window.getActiveWebview ? window.getActiveWebview() : (typeof getActiveWebview === 'function' ? getActiveWebview() : null);
        if (!activeWebview || typeof activeWebview.executeJavaScript !== "function" || activeWebview.getURL() === "about:blank") {
          codeOutput.style.opacity = "0";
          codeOutput.style.transform = "translateY(5px)";
          codeOutput.textContent = "[Error] No active webview with a loaded website.";
          codeOutput.style.color = "#f38ba8";
          setTimeout(() => {
            codeOutput.style.transition = "all 0.3s ease";
            codeOutput.style.opacity = "1";
            codeOutput.style.transform = "translateY(0)";
          }, 10);
        } else {
          // Evaluate code in the webview context
          let result;
          try {
            result = await activeWebview.executeJavaScript(code, true);
            codeOutput.style.opacity = "0";
            codeOutput.style.transform = "translateY(5px)";
            codeOutput.textContent = typeof result !== "undefined" ? String(result) : "[No output]";
            codeOutput.style.color = "";
            setTimeout(() => {
              codeOutput.style.transition = "all 0.3s ease";
              codeOutput.style.opacity = "1";
              codeOutput.style.transform = "translateY(0)";
            }, 10);
          } catch (e) {
            codeOutput.style.opacity = "0";
            codeOutput.style.transform = "translateY(5px)";
            codeOutput.textContent = "[Exception] " + e.message;
            codeOutput.style.color = "#f38ba8";
            setTimeout(() => {
              codeOutput.style.transition = "all 0.3s ease";
              codeOutput.style.opacity = "1";
              codeOutput.style.transform = "translateY(0)";
            }, 10);
          }
        }
      } finally {
        // Reset button
        codeRunBtn.disabled = false;
        codeRunBtn.innerHTML = '<i class="fas fa-play"></i> Run';
      }
    });
  }

  if (codeCopyBtn) {
    codeCopyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(codeInput.value || "");
      codeCopyBtn.classList.add("copied");
      codeCopyBtn.innerHTML = '<i class="fas fa-check"></i> Copied';
      setTimeout(() => {
        codeCopyBtn.classList.remove("copied");
        codeCopyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
      }, 900);
    });
  }

  if (codeOutputCopyBtn) {
    codeOutputCopyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(codeOutput.textContent || "");
      codeOutputCopyBtn.classList.add("copied");
      setTimeout(() => codeOutputCopyBtn.classList.remove("copied"), 900);
    });
  }
})();
