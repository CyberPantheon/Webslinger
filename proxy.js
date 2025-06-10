const { ipcRenderer } = require('electron');

let mitmwebUrl = null; // Store the URL received from main process

document.addEventListener('DOMContentLoaded', () => {
    const webview = document.getElementById('mitmweb-view');
    const statusIndicator = document.getElementById('webview-status');
    const loadingOverlay = document.getElementById('loading-overlay');
    const minimizeBtn = document.getElementById("minimize-btn");
    const closeBtn = document.getElementById("close-btn");

    // --- Basic Checks ---
    if (!webview) {
        console.error('Error: Could not find webview element with id "mitmweb-view"');
        if(statusIndicator) statusIndicator.textContent = 'Error: UI Element Missing!';
        return;
    }
    if (!statusIndicator) {
        console.warn('Warning: Status indicator element "webview-status" not found.');
    }
    if (!loadingOverlay) {
        console.warn('Warning: Loading overlay element "loading-overlay" not found.');
    } else {
        loadingOverlay.classList.remove('hidden'); // Show loading overlay initially
    }


    // --- Window Controls ---
    if (minimizeBtn) {
        minimizeBtn.addEventListener("click", () => {
            ipcRenderer.send("minimize-window"); // Ask main process to minimize
        });
    } else {
        console.warn('Warning: Minimize button element "minimize-btn" not found.');
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            ipcRenderer.send("close-window"); // Ask main process to close
        });
    } else {
        console.warn('Warning: Close button element "close-btn" not found.');
    }


    console.log('Proxy renderer loaded. Waiting for mitmweb URL from main process...');
    if(statusIndicator) {
        statusIndicator.textContent = 'Waiting for URL...';
        statusIndicator.className = 'status-indicator loading'; // Use 'loading' style
    }


    // --- IPC Listener for URL ---
    ipcRenderer.on('set-mitmweb-url', (event, url) => {
        console.log('Received mitmweb URL:', url);
        mitmwebUrl = url; // Store the URL

        if (webview && url) {
            if(statusIndicator) {
                statusIndicator.textContent = `Loading: ${url}`;
                statusIndicator.className = 'status-indicator loading';
            }
            webview.src = url; // Set the webview source <<< This is the crucial step
        } else {
             console.error('Received URL but webview element not found or URL is invalid!');
             if(statusIndicator) {
                 statusIndicator.textContent = 'Error: Invalid URL or UI';
                 statusIndicator.className = 'status-indicator error';
             }
             if(loadingOverlay) loadingOverlay.classList.add('hidden'); // Hide loading on error
        }
    });


    // --- Webview Event Listeners ---
    webview.addEventListener('did-start-loading', () => {
        const currentSrc = webview.src;
        console.log('Webview started loading:', currentSrc);
         if(statusIndicator && currentSrc && currentSrc !== 'about:blank') {
             statusIndicator.textContent = `Loading: ${currentSrc}`;
             statusIndicator.className = 'status-indicator loading';
         }
         if(loadingOverlay && currentSrc && currentSrc !== 'about:blank') loadingOverlay.classList.remove('hidden');
    });

    // --- Proxy Authentication Handler for HTTP/HTTPS proxies ---
    webview.addEventListener('login', async (event, request, authInfo, callback) => {
        if (authInfo.isProxy) {
            event.preventDefault();
            try {
                // Ask main process for credentials
                const credentials = await ipcRenderer.invoke('proxy:get-auth-credentials');
                if (credentials && credentials.username) {
                    callback(credentials.username, credentials.password || '');
                    console.log('[Proxy Renderer] Provided proxy credentials for authentication.');
                } else {
                    callback(); // No credentials, deny
                    console.warn('[Proxy Renderer] No proxy credentials available, denying authentication.');
                }
            } catch (err) {
                callback();
                console.error('[Proxy Renderer] Error retrieving proxy credentials:', err);
            }
        } else {
            // Not a proxy auth request, let it proceed
            callback();
        }
    });

    webview.addEventListener('did-finish-load', () => {
        const currentSrc = webview.src;
        console.log('Webview finished loading:', currentSrc);
        if (currentSrc && currentSrc !== 'about:blank' && !currentSrc.startsWith('data:')) {
             if(statusIndicator) {
                statusIndicator.textContent = `Ready: ${mitmwebUrl}`; // Show the intended URL
                statusIndicator.className = 'status-indicator ready';
            }
             if(loadingOverlay) loadingOverlay.classList.add('hidden'); // Hide loading overlay
         }
    });

    webview.addEventListener('did-fail-load', (error) => {
        // Ignore failures for 'about:blank' or internal data URLs used for error messages
        if (!error.validatedURL || error.validatedURL === "about:blank" || error.validatedURL.startsWith('data:')) return;

        console.error('Webview failed to load:', error.errorCode, error.errorDescription, error.validatedURL);
        if(statusIndicator) {
            statusIndicator.textContent = `Load Failed: ${error.errorCode}`;
            statusIndicator.className = 'status-indicator error';
        }
        if(loadingOverlay) loadingOverlay.classList.add('hidden'); // Hide loading overlay

        // Display a user-friendly error message *inside* the webview
        const errorMessageHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <link rel="stylesheet" href="proxy.css">
                <title>Load Error</title>
            </head>
            <body>
                <div class="webview-message error">
                    <h2>Failed to load Mitmweb Interface</h2>
                    <p>Could not load: <code>${error.validatedURL || mitmwebUrl || 'N/A'}</code></p>
                    <p>Error: ${error.errorDescription} (${error.errorCode})</p>
                    <p>Please ensure mitmweb is running correctly on <code>${mitmwebUrl || 'http://127.0.0.1:8081'}</code> and is accessible. Check the PowerShell script and console logs in the main application window for details.</p>
                    <button onclick="location.reload()">Retry Load</button>
                </div>
            </body>
            </html>
        `;
        // Load the error message as a data URL
        webview.loadURL(`http://127.0.0.1:8081`);
    });

    webview.addEventListener('dom-ready', () => {
      // Check if the loaded content is our error message or the actual site
      if (!webview.src.startsWith('data:')) {
          console.log('Webview DOM ready for:', webview.src);
          if(statusIndicator && statusIndicator.textContent.startsWith('Loading')) {
             statusIndicator.textContent = `Rendering: ${mitmwebUrl}`;
          }
          // You could potentially inject CSS or JS here if needed
          // Example: webview.insertCSS('body { background-color: #111 !important; }');
      }
    });

}); // End DOMContentLoaded