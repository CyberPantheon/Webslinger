// Add this event listener to handle opening URLs in the webview
const { ipcRenderer } = require("electron")

// Listen for the open-url-in-webview event
ipcRenderer.on("open-url-in-webview", (event, url) => {
  // Get the webview element
  const webview = document.getElementById("webview")

  // If webview exists, load the URL
  if (webview) {
    // Make sure webview is visible
    webview.style.display = "flex"
    const homeContent = document.getElementById("home-content")
    if (homeContent) {
      homeContent.style.display = "none"
    }

    // Load the URL
    webview.src = url

    // Update search input if it exists
    const searchInput = document.getElementById("search-input")
    if (searchInput) {
      searchInput.value = url
    }
  }
})

