const { ipcRenderer } = require("electron")
const dns = require("dns").promises
const SimpleHtmlParser = require("./simple-html-parser")

document.addEventListener("DOMContentLoaded", () => {
  // Window controls
  const minimizeBtn = document.getElementById("minimize-btn")
  minimizeBtn.addEventListener("click", () => {
    console.log("Minimize button clicked")
    ipcRenderer.send("minimize-window")
  })

  const closeBtn = document.getElementById("close-btn")
  closeBtn.addEventListener("click", () => {
    console.log("Close button clicked")
    ipcRenderer.send("close-window")
  })

  // URL input and analyze button
  const urlInput = document.getElementById("url-input")
  const analyzeBtn = document.getElementById("analyze-btn")
  const loadingOverlay = document.getElementById("loading-overlay")

  // Options
  const followRedirects = document.getElementById("follow-redirects")
  const deepScan = document.getElementById("deep-scan")

  // Tab switching
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelector(".tab.active").classList.remove("active")
      tab.classList.add("active")

      // Switch content based on tab
      const tabName = tab.dataset.tab
      document.querySelectorAll(".tab-content").forEach((content) => {
        content.classList.remove("active")
      })
      document.getElementById(`${tabName}-tab`).classList.add("active")
    })
  })

  // Analyze button click handler
  analyzeBtn.addEventListener("click", () => {
    analyzeWebsite()
  })

  // Enter key in URL input
  urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      analyzeWebsite()
    }
  })

  // Function to analyze website
  async function analyzeWebsite() {
    let url = urlInput.value.trim()

    // Validate URL
    if (!url) {
      showNotification("Please enter a URL to analyze", "error")
      return
    }

    // Add protocol if missing
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url
      urlInput.value = url
    }

    try {
      // Show loading overlay
      loadingOverlay.style.display = "flex"

      // Get options
      const options = {
        followRedirects: followRedirects.checked,
        deepScan: deepScan.checked,
        // Add more options if needed
      }

      // Call main process to analyze website
      const result = await ipcRenderer.invoke("analyze-website", url, options)

      // If deep scan is enabled, get additional information
      if (options.deepScan) {
        // Get domain information
        const domain = new URL(url).hostname
        const domainInfo = await getDomainInfo(domain)
        result.domainInfo = domainInfo

        // Get DNS records
        const dnsRecords = await getDnsRecords(domain)
        result.dnsRecords = dnsRecords

        // Perform deeper analysis
        await performDeepAnalysis(result, url)

        // Discover endpoints and sensitive files
        result.endpointDiscovery = await discoverEndpoints(url)
        result.sensitiveFiles = await checkSensitiveFiles(url)

        // Check for open ports (basic scan)
        result.openPorts = await scanOpenPorts(domain)

        // Screenshot (if supported)
        try {
          result.screenshot = await ipcRenderer.invoke("take-screenshot", url)
        } catch (e) {
          result.screenshot = null
        }
      }

      // Hide loading overlay
      loadingOverlay.style.display = "none"

      if (result.error) {
        showNotification(`Error: ${result.error}`, "error")
        return
      }

      // Update UI with results
      updateResults(result)

      showNotification("Website analysis complete", "success")
    } catch (error) {
      loadingOverlay.style.display = "none"
      showNotification(`Error: ${error.message}`, "error")
      console.error("Error analyzing website:", error)
    }
  }

  // Discover endpoints and admin panels using common wordlists
  async function discoverEndpoints(url) {
    const commonEndpoints = [
      "admin", "login", "dashboard", "cpanel", "phpmyadmin", "wp-admin", "config", "setup", "register", "signup", "user", "api", "test", "backup", "old", "dev"
    ]
    const found = []
    for (const ep of commonEndpoints) {
      try {
        const testUrl = url.replace(/\/$/, "") + "/" + ep
        const res = await fetch(testUrl, { method: "HEAD" })
        if (res.status < 400) found.push({ endpoint: ep, url: testUrl, status: res.status })
      } catch (e) { /* ignore */ }
    }
    return found
  }

  // Check for sensitive files
  async function checkSensitiveFiles(url) {
    const files = [".env", ".git/config", "robots.txt", ".htaccess", "backup.zip", "db.sql", "config.php~", "wp-config.php.bak"]
    const found = []
    for (const file of files) {
      try {
        const testUrl = url.replace(/\/$/, "") + "/" + file
        const res = await fetch(testUrl, { method: "HEAD" })
        if (res.status < 400) found.push({ file, url: testUrl, status: res.status })
      } catch (e) { /* ignore */ }
    }
    return found
  }

  // Basic open port scan (common ports only, TCP connect)
  async function scanOpenPorts(domain) {
    // Only works if backend supports it, otherwise skip
    try {
      return await ipcRenderer.invoke("scan-open-ports", domain)
    } catch (e) {
      return []
    }
  }

  // Function to perform deeper analysis
  async function performDeepAnalysis(result, url) {
    try {
      // Analyze JavaScript files
      if (result.scripts && result.scripts.length > 0) {
        const jsAnalysis = await ipcRenderer.invoke("analyze-js-files", result.scripts.slice(0, 5))
        result.jsAnalysis = jsAnalysis
      }

      // Analyze subdomains if available (brute-force)
      if (result.dnsRecords && result.dnsRecords.a) {
        const domain = new URL(url).hostname
        const baseDomain = domain.split(".").slice(-2).join(".")
        // Use a larger wordlist for brute-force
        const subdomainAnalysis = await ipcRenderer.invoke("analyze-subdomains", baseDomain, { bruteForce: true })
        result.subdomainAnalysis = subdomainAnalysis
      }

      // Analyze security posture
      const securityAnalysis = await ipcRenderer.invoke("analyze-security", url, result.headers)
      result.securityAnalysis = securityAnalysis

      // Analyze performance metrics
      const performanceAnalysis = await ipcRenderer.invoke("analyze-performance", url)
      result.performanceAnalysis = performanceAnalysis

      // Detect more technologies (WAF, CDN, reverse proxy, programming language, DB, mail provider, etc)
      result.extendedTech = await ipcRenderer.invoke("detect-extended-tech", url, result.headers)

      // Check for CORS misconfigurations
      result.cors = await ipcRenderer.invoke("check-cors", url)

      // Check for open redirects
      result.openRedirects = await ipcRenderer.invoke("check-open-redirects", url)

      // Directory listing check
      result.dirListing = await ipcRenderer.invoke("check-dir-listing", url)

      // Default credentials check (if possible)
      result.defaultCreds = await ipcRenderer.invoke("check-default-creds", url)

      return result
    } catch (error) {
      console.error("Error in deep analysis:", error)
      return result
    }
  }

  // Function to get domain information
  async function getDomainInfo(domain) {
    try {
      // Call main process to get WHOIS information
      return await ipcRenderer.invoke("get-domain-info", domain)
    } catch (error) {
      console.error("Error getting domain info:", error)
      return { error: error.message }
    }
  }

  // Function to get DNS records
  async function getDnsRecords(domain) {
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

  // Function to update results UI
  function updateResults(data) {
    // Update site title and URL
    document.getElementById("site-title").textContent = data.title || "Website Analysis Results"
    document.getElementById("site-url").textContent = data.url

    // Update basic information
    updateBasicInfo(data)

    // Update technology summary
    updateTechSummary(data)

    // Update security summary
    updateSecuritySummary(data)

    // Update meta information
    updateMetaInfo(data)

    // Update server technologies
    updateServerTech(data)

    // Update client technologies
    updateClientTech(data)

    // Update frameworks
    updateFrameworks(data)

    // Update CMS information
    updateCmsInfo(data)

    // Update libraries
    updateLibraries(data)

    // Update analytics
    updateAnalytics(data)

    // Update server information
    updateServerInfo(data)

    // Update DNS records
    updateDnsRecords(data)

    // Update hosting information
    updateHostingInfo(data)

    // Update IP information
    updateIpInfo(data)

    // Update security headers
    updateSecurityHeaders(data)

    // Update SSL/TLS information
    updateSslInfo(data)

    // Update cookie security
    updateCookieSecurity(data)

    // Update potential vulnerabilities
    updateVulnerabilities(data)

    // Update HTML structure
    updateHtmlStructure(data)

    // Update JavaScript files
    updateJsFiles(data)

    // Update CSS files
    updateCssFiles(data)

    // Update images
    updateImages(data)

    // Update forms
    updateForms(data)

    // Update external links
    updateExternalLinks(data)

    // Update domain registration
    updateDomainRegistration(data)

    // Update WHOIS information
    updateWhoisInfo(data)

    // Update domain history
    updateDomainHistory(data)

    // Update deep analysis results if available
    if (data.jsAnalysis) updateJsAnalysis(data.jsAnalysis)
    if (data.subdomainAnalysis) updateSubdomainAnalysis(data.subdomainAnalysis)
    if (data.securityAnalysis) updateSecurityAnalysis(data.securityAnalysis)
    if (data.performanceAnalysis) updatePerformanceAnalysis(data.performanceAnalysis)

    // New: Update extended technology detection
    if (data.extendedTech) updateExtendedTech(data.extendedTech)

    // New: Update endpoint discovery
    if (data.endpointDiscovery) updateEndpointDiscovery(data.endpointDiscovery)

    // New: Update sensitive files
    if (data.sensitiveFiles) updateSensitiveFiles(data.sensitiveFiles)

    // New: Update open ports
    if (data.openPorts) updateOpenPorts(data.openPorts)

    // New: Update screenshot
    if (data.screenshot) updateScreenshot(data.screenshot)
  }

  // Function to update JavaScript analysis
  function updateJsAnalysis(jsAnalysis) {
    // Create a new card for JS analysis
    const jsAnalysisCard = document.createElement("div")
    jsAnalysisCard.className = "result-card"
    jsAnalysisCard.innerHTML = `
      <div class="card-header">
        <i class="fas fa-code"></i>
        <h3>JavaScript Analysis</h3>
      </div>
      <div class="card-content" id="js-analysis">
        <h4>Libraries Detected</h4>
        <ul>
          ${jsAnalysis.libraries.map((lib) => `<li>${lib.name} - ${lib.version || "Unknown version"}</li>`).join("")}
        </ul>
        
        <h4>Potential Issues</h4>
        <ul>
          ${jsAnalysis.issues.map((issue) => `<li>${issue.description} - ${issue.severity}</li>`).join("")}
        </ul>
      </div>
    `

    // Add to the tech stack tab
    document.querySelector("#tech-stack-tab .results-grid").appendChild(jsAnalysisCard)
  }

  // Function to update subdomain analysis
  function updateSubdomainAnalysis(subdomainAnalysis) {
    // Create a new card for subdomain analysis
    const subdomainCard = document.createElement("div")
    subdomainCard.className = "result-card"
    subdomainCard.innerHTML = `
      <div class="card-header">
        <i class="fas fa-sitemap"></i>
        <h3>Subdomain Analysis</h3>
      </div>
      <div class="card-content" id="subdomain-analysis">
        <h4>Discovered Subdomains</h4>
        <ul>
          ${subdomainAnalysis.subdomains.map((sub) => `<li>${sub.name} - ${sub.ip || "No IP"}</li>`).join("")}
        </ul>
      </div>
    `

    // Add to the infrastructure tab
    document.querySelector("#infrastructure-tab .results-grid").appendChild(subdomainCard)
  }

  // Function to update security analysis
  function updateSecurityAnalysis(securityAnalysis) {
    // Create a new card for security analysis
    const securityCard = document.createElement("div")
    securityCard.className = "result-card"
    securityCard.innerHTML = `
      <div class="card-header">
        <i class="fas fa-shield-alt"></i>
        <h3>Advanced Security Analysis</h3>
      </div>
      <div class="card-content" id="advanced-security">
        <h4>Security Score: ${securityAnalysis.score}/100</h4>
        
        <h4>Critical Issues</h4>
        <ul>
          ${securityAnalysis.criticalIssues.map((issue) => `<li>${issue}</li>`).join("")}
        </ul>
        
        <h4>Recommendations</h4>
        <ul>
          ${securityAnalysis.recommendations.map((rec) => `<li>${rec}</li>`).join("")}
        </ul>
      </div>
    `

    // Add to the security tab
    document.querySelector("#security-tab .results-grid").appendChild(securityCard)
  }

  // Function to update performance analysis
  function updatePerformanceAnalysis(performanceAnalysis) {
    // Create a new card for performance analysis
    const perfCard = document.createElement("div")
    perfCard.className = "result-card"
    perfCard.innerHTML = `
      <div class="card-header">
        <i class="fas fa-tachometer-alt"></i>
        <h3>Performance Analysis</h3>
      </div>
      <div class="card-content" id="performance-analysis">
        <h4>Load Time: ${performanceAnalysis.loadTime}ms</h4>
        <h4>Page Size: ${performanceAnalysis.pageSize}</h4>
        
        <h4>Optimizations</h4>
        <ul>
          ${performanceAnalysis.optimizations.map((opt) => `<li>${opt}</li>`).join("")}
        </ul>
      </div>
    `

    // Add to the overview tab
    document.querySelector("#overview-tab .results-grid").appendChild(perfCard)
  }

  // Function to update basic information
  function updateBasicInfo(data) {
    const basicInfoEl = document.getElementById("basic-info")
    basicInfoEl.innerHTML = ""

    // Add title
    const titleItem = document.createElement("div")
    titleItem.className = "tech-item"
    titleItem.innerHTML = `
      <div class="item-name">Title</div>
      <div class="item-value">${data.title || "No title found"}</div>
    `
    basicInfoEl.appendChild(titleItem)

    // Add URL
    const urlItem = document.createElement("div")
    urlItem.className = "tech-item"
    urlItem.innerHTML = `
      <div class="item-name">URL</div>
      <div class="item-value">${data.url}</div>
    `
    basicInfoEl.appendChild(urlItem)

    // Add status code
    const statusItem = document.createElement("div")
    statusItem.className = "tech-item"
    statusItem.innerHTML = `
      <div class="item-name">Status Code</div>
      <div class="item-value">${data.status}</div>
    `
    basicInfoEl.appendChild(statusItem)

    // Add content type if available
    if (data.headers && data.headers["content-type"]) {
      const contentTypeItem = document.createElement("div")
      contentTypeItem.className = "tech-item"
      contentTypeItem.innerHTML = `
        <div class="item-name">Content Type</div>
        <div class="item-value">${data.headers["content-type"]}</div>
      `
      basicInfoEl.appendChild(contentTypeItem)
    }
  }

  // Function to update technology summary
  function updateTechSummary(data) {
    const techSummaryEl = document.getElementById("tech-summary")
    techSummaryEl.innerHTML = ""

    if (data.technologies && data.technologies.length > 0) {
      const techList = document.createElement("div")
      techList.className = "badge-list"

      data.technologies.forEach((tech) => {
        const techBadge = document.createElement("span")
        techBadge.className = "badge badge-primary"
        techBadge.textContent = `${tech.name}: ${tech.value}`
        techList.appendChild(techBadge)
      })

      techSummaryEl.appendChild(techList)
    } else {
      techSummaryEl.innerHTML = "<div class='placeholder'>No technology information detected</div>"
    }
  }

  // Function to update security summary
  function updateSecuritySummary(data) {
    const securitySummaryEl = document.getElementById("security-summary")
    securitySummaryEl.innerHTML = ""

    // Check for HTTPS
    const httpsItem = document.createElement("div")
    httpsItem.className = "tech-item"

    if (data.url.startsWith("https://")) {
      httpsItem.innerHTML = `
        <div class="item-name">HTTPS</div>
        <div class="item-value"><span class="security-status status-good">Enabled</span></div>
      `
    } else {
      httpsItem.innerHTML = `
        <div class="item-name">HTTPS</div>
        <div class="item-value"><span class="security-status status-bad">Disabled</span></div>
      `
    }

    securitySummaryEl.appendChild(httpsItem)

    // Check for security headers
    const securityHeaders = [
      { name: "Content-Security-Policy", header: "content-security-policy" },
      { name: "X-XSS-Protection", header: "x-xss-protection" },
      { name: "X-Frame-Options", header: "x-frame-options" },
      { name: "X-Content-Type-Options", header: "x-content-type-options" },
      { name: "Strict-Transport-Security", header: "strict-transport-security" },
    ]

    let securityScore = 0
    const totalHeaders = securityHeaders.length

    securityHeaders.forEach((header) => {
      if (data.headers && data.headers[header.header]) {
        securityScore++
      }
    })

    const securityScoreItem = document.createElement("div")
    securityScoreItem.className = "tech-item"

    let scoreStatus = "status-bad"
    if (securityScore >= totalHeaders - 1) {
      scoreStatus = "status-good"
    } else if (securityScore >= totalHeaders / 2) {
      scoreStatus = "status-warning"
    }

    securityScoreItem.innerHTML = `
      <div class="item-name">Security Score</div>
      <div class="item-value">
        <span class="security-status ${scoreStatus}">${securityScore}/${totalHeaders}</span>
      </div>
    `

    securitySummaryEl.appendChild(securityScoreItem)
  }

  // Function to update meta information
  function updateMetaInfo(data) {
    const metaInfoEl = document.getElementById("meta-info")

    if (data.metaTags && data.metaTags.length > 0) {
      metaInfoEl.innerHTML = ""

      // Filter important meta tags first
      const importantTags = ["description", "keywords", "author", "viewport", "robots"]

      // Display important tags first
      importantTags.forEach((tagName) => {
        const tag = data.metaTags.find((meta) => meta.name.toLowerCase() === tagName)
        if (tag) {
          const metaItem = document.createElement("div")
          metaItem.className = "meta-item"
          metaItem.innerHTML = `
            <div class="item-name">${tag.name}</div>
            <div class="item-value">${tag.content}</div>
          `
          metaInfoEl.appendChild(metaItem)
        }
      })

      // Display other tags
      data.metaTags.forEach((meta) => {
        if (!importantTags.includes(meta.name.toLowerCase())) {
          const metaItem = document.createElement("div")
          metaItem.className = "meta-item"
          metaItem.innerHTML = `
            <div class="item-name">${meta.name}</div>
            <div class="item-value">${meta.content}</div>
          `
          metaInfoEl.appendChild(metaItem)
        }
      })
    } else {
      metaInfoEl.innerHTML = "<div class='placeholder'>No meta information detected</div>"
    }
  }

  // Function to update server technologies
  function updateServerTech(data) {
    const serverTechEl = document.getElementById("server-tech")
    serverTechEl.innerHTML = ""

    let serverTechFound = false

    // Server software
    if (data.headers && data.headers["server"]) {
      serverTechFound = true
      const serverItem = document.createElement("div")
      serverItem.className = "tech-item"
      serverItem.innerHTML = `
        <div class="item-name">Server</div>
        <div class="item-value">${data.headers["server"]}</div>
      `
      serverTechEl.appendChild(serverItem)
    }

    // Backend framework
    if (data.headers && data.headers["x-powered-by"]) {
      serverTechFound = true
      const frameworkItem = document.createElement("div")
      frameworkItem.className = "tech-item"
      frameworkItem.innerHTML = `
        <div class="item-name">Framework</div>
        <div class="item-value">${data.headers["x-powered-by"]}</div>
      `
      serverTechEl.appendChild(frameworkItem)
    }

    // Server-side technologies from detection
    if (data.technologies) {
      const serverTechs = data.technologies.filter((tech) =>
        ["Server", "Powered By", "CMS", "Backend"].includes(tech.name),
      )

      serverTechs.forEach((tech) => {
        if (tech.name !== "Server" || !data.headers || !data.headers["server"]) {
          serverTechFound = true
          const techItem = document.createElement("div")
          techItem.className = "tech-item"
          techItem.innerHTML = `
            <div class="item-name">${tech.name}</div>
            <div class="item-value">${tech.value}</div>
          `
          serverTechEl.appendChild(techItem)
        }
      })
    }

    if (!serverTechFound) {
      serverTechEl.innerHTML = "<div class='placeholder'>No server technologies detected</div>"
    }
  }

  // Function to update client technologies
  function updateClientTech(data) {
    const clientTechEl = document.getElementById("client-tech")
    clientTechEl.innerHTML = ""

    let clientTechFound = false

    // Client-side technologies from detection
    if (data.technologies) {
      const clientTechs = data.technologies.filter((tech) =>
        ["Frontend", "JavaScript", "UI", "Framework"].includes(tech.name),
      )

      clientTechs.forEach((tech) => {
        clientTechFound = true
        const techItem = document.createElement("div")
        techItem.className = "tech-item"
        techItem.innerHTML = `
          <div class="item-name">${tech.name}</div>
          <div class="item-value">${tech.value}</div>
        `
        clientTechEl.appendChild(techItem)
      })
    }

    if (!clientTechFound) {
      clientTechEl.innerHTML = "<div class='placeholder'>No client technologies detected</div>"
    }
  }

  // Function to update frameworks
  function updateFrameworks(data) {
    const frameworksEl = document.getElementById("frameworks")
    frameworksEl.innerHTML = ""

    let frameworksFound = false

    // Frameworks from detection
    if (data.technologies) {
      const frameworks = data.technologies.filter(
        (tech) => tech.name === "Framework" || tech.value.includes("Framework"),
      )

      frameworks.forEach((tech) => {
        frameworksFound = true
        const frameworkItem = document.createElement("div")
        frameworkItem.className = "tech-item"
        frameworkItem.innerHTML = `
          <div class="item-name">${tech.name}</div>
          <div class="item-value">${tech.value}</div>
        `
        frameworksEl.appendChild(frameworkItem)
      })
    }

    if (!frameworksFound) {
      frameworksEl.innerHTML = "<div class='placeholder'>No frameworks detected</div>"
    }
  }

  // Function to update CMS information
  function updateCmsInfo(data) {
    const cmsInfoEl = document.getElementById("cms-info")
    cmsInfoEl.innerHTML = ""

    let cmsFound = false

    // CMS from detection
    if (data.technologies) {
      const cms = data.technologies.filter((tech) => tech.name === "CMS")

      cms.forEach((tech) => {
        cmsFound = true
        const cmsItem = document.createElement("div")
        cmsItem.className = "tech-item"
        cmsItem.innerHTML = `
          <div class="item-name">CMS</div>
          <div class="item-value">${tech.value}</div>
        `
        cmsInfoEl.appendChild(cmsItem)
      })
    }

    if (!cmsFound) {
      cmsInfoEl.innerHTML = "<div class='placeholder'>No CMS detected</div>"
    }
  }

  // Function to update libraries
  function updateLibraries(data) {
    const librariesEl = document.getElementById("libraries")
    librariesEl.innerHTML = ""

    let librariesFound = false

    // Libraries from scripts
    if (data.scripts && data.scripts.length > 0) {
      const libraries = []

      // Common library patterns
      const libraryPatterns = [
        { pattern: /jquery/i, name: "jQuery" },
        { pattern: /bootstrap/i, name: "Bootstrap" },
        { pattern: /react/i, name: "React" },
        { pattern: /angular/i, name: "Angular" },
        { pattern: /vue/i, name: "Vue.js" },
        { pattern: /lodash/i, name: "Lodash" },
        { pattern: /moment/i, name: "Moment.js" },
        { pattern: /d3/i, name: "D3.js" },
        { pattern: /three/i, name: "Three.js" },
        { pattern: /gsap/i, name: "GSAP" },
      ]

      data.scripts.forEach((script) => {
        libraryPatterns.forEach((lib) => {
          if (lib.pattern.test(script) && !libraries.includes(lib.name)) {
            libraries.push(lib.name)
          }
        })
      })

      if (libraries.length > 0) {
        librariesFound = true

        libraries.forEach((lib) => {
          const libItem = document.createElement("div")
          libItem.className = "tech-item"
          libItem.innerHTML = `
            <div class="item-name">Library</div>
            <div class="item-value">${lib}</div>
          `
          librariesEl.appendChild(libItem)
        })
      }
    }

    if (!librariesFound) {
      librariesEl.innerHTML = "<div class='placeholder'>No libraries detected</div>"
    }
  }

  // Function to update analytics
  function updateAnalytics(data) {
    const analyticsEl = document.getElementById("analytics")
    analyticsEl.innerHTML = ""

    let analyticsFound = false

    // Analytics from detection
    if (data.technologies) {
      const analytics = data.technologies.filter((tech) => tech.name === "Analytics")

      analytics.forEach((tech) => {
        analyticsFound = true
        const analyticsItem = document.createElement("div")
        analyticsItem.className = "tech-item"
        analyticsItem.innerHTML = `
          <div class="item-name">Analytics</div>
          <div class="item-value">${tech.value}</div>
        `
        analyticsEl.appendChild(analyticsItem)
      })
    }

    // Check for common analytics patterns in scripts
    if (data.scripts && data.scripts.length > 0) {
      const analyticsPatterns = [
        { pattern: /google-analytics/i, name: "Google Analytics" },
        { pattern: /gtag/i, name: "Google Tag Manager" },
        { pattern: /hotjar/i, name: "Hotjar" },
        { pattern: /matomo/i, name: "Matomo" },
        { pattern: /piwik/i, name: "Piwik" },
        { pattern: /segment/i, name: "Segment" },
        { pattern: /mixpanel/i, name: "Mixpanel" },
        { pattern: /facebook.*pixel/i, name: "Facebook Pixel" },
      ]

      data.scripts.forEach((script) => {
        analyticsPatterns.forEach((analytics) => {
          if (analytics.pattern.test(script)) {
            analyticsFound = true
            const analyticsItem = document.createElement("div")
            analyticsItem.className = "tech-item"
            analyticsItem.innerHTML = `
              <div class="item-name">Analytics</div>
              <div class="item-value">${analytics.name}</div>
            `
            analyticsEl.appendChild(analyticsItem)
          }
        })
      })
    }

    if (!analyticsFound) {
      analyticsEl.innerHTML = "<div class='placeholder'>No analytics tools detected</div>"
    }
  }

  // Function to update server information
  function updateServerInfo(data) {
    const serverInfoEl = document.getElementById("server-info")
    serverInfoEl.innerHTML = ""

    // Add server header if available
    if (data.headers && data.headers["server"]) {
      const serverItem = document.createElement("div")
      serverItem.className = "tech-item"
      serverItem.innerHTML = `
        <div class="item-name">Server</div>
        <div class="item-value">${data.headers["server"]}</div>
      `
      serverInfoEl.appendChild(serverItem)
    }

    // Add status code
    const statusItem = document.createElement("div")
    statusItem.className = "tech-item"
    statusItem.innerHTML = `
      <div class="item-name">Status Code</div>
      <div class="item-value">${data.status}</div>
    `
    serverInfoEl.appendChild(statusItem)

    // Add content type if available
    if (data.headers && data.headers["content-type"]) {
      const contentTypeItem = document.createElement("div")
      contentTypeItem.className = "tech-item"
      contentTypeItem.innerHTML = `
        <div class="item-name">Content Type</div>
        <div class="item-value">${data.headers["content-type"]}</div>
      `
      serverInfoEl.appendChild(contentTypeItem)
    }

    // Add other interesting headers
    const interestingHeaders = [
      "x-powered-by",
      "x-aspnet-version",
      "x-aspnetmvc-version",
      "x-drupal-cache",
      "x-generator",
      "x-drupal-dynamic-cache",
      "x-varnish",
      "via",
    ]

    interestingHeaders.forEach((header) => {
      if (data.headers && data.headers[header]) {
        const headerItem = document.createElement("div")
        headerItem.className = "tech-item"
        headerItem.innerHTML = `
          <div class="item-name">${header}</div>
          <div class="item-value">${data.headers[header]}</div>
        `
        serverInfoEl.appendChild(headerItem)
      }
    })
  }

  // Function to update DNS records
  function updateDnsRecords(data) {
    const dnsRecordsEl = document.getElementById("dns-records")

    if (data.dnsRecords && !data.dnsRecords.error) {
      dnsRecordsEl.innerHTML = ""

      // A records
      if (data.dnsRecords.a && data.dnsRecords.a.length > 0) {
        const aRecordItem = document.createElement("div")
        aRecordItem.className = "dns-item"
        aRecordItem.innerHTML = `
          <div class="item-name">A Records</div>
          <div class="item-value">${data.dnsRecords.a.join(", ")}</div>
        `
        dnsRecordsEl.appendChild(aRecordItem)
      }

      // AAAA records
      if (data.dnsRecords.aaaa && data.dnsRecords.aaaa.length > 0) {
        const aaaaRecordItem = document.createElement("div")
        aaaaRecordItem.className = "dns-item"
        aaaaRecordItem.innerHTML = `
          <div class="item-name">AAAA Records</div>
          <div class="item-value">${data.dnsRecords.aaaa.join(", ")}</div>
        `
        dnsRecordsEl.appendChild(aaaaRecordItem)
      }

      // MX records
      if (data.dnsRecords.mx && data.dnsRecords.mx.length > 0) {
        const mxRecordItem = document.createElement("div")
        mxRecordItem.className = "dns-item"

        const mxValues = data.dnsRecords.mx.map((record) => `${record.exchange} (priority: ${record.priority})`)

        mxRecordItem.innerHTML = `
          <div class="item-name">MX Records</div>
          <div class="item-value">${mxValues.join("<br>")}</div>
        `
        dnsRecordsEl.appendChild(mxRecordItem)
      }

      // NS records
      if (data.dnsRecords.ns && data.dnsRecords.ns.length > 0) {
        const nsRecordItem = document.createElement("div")
        nsRecordItem.className = "dns-item"
        nsRecordItem.innerHTML = `
          <div class="item-name">NS Records</div>
          <div class="item-value">${data.dnsRecords.ns.join("<br>")}</div>
        `
        dnsRecordsEl.appendChild(nsRecordItem)
      }

      // TXT records
      if (data.dnsRecords.txt && data.dnsRecords.txt.length > 0) {
        const txtRecordItem = document.createElement("div")
        txtRecordItem.className = "dns-item"

        const txtValues = data.dnsRecords.txt.map((record) => (Array.isArray(record) ? record.join("") : record))

        txtRecordItem.innerHTML = `
          <div class="item-name">TXT Records</div>
          <div class="item-value">${txtValues.join("<br>")}</div>
        `
        dnsRecordsEl.appendChild(txtRecordItem)
      }
    } else {
      dnsRecordsEl.innerHTML = "<div class='placeholder'>No DNS records available</div>"
    }
  }

  // Function to update hosting information
  function updateHostingInfo(data) {
    const hostingInfoEl = document.getElementById("hosting-info")
    hostingInfoEl.innerHTML = ""

    let hostingFound = false

    // Try to determine hosting provider from headers and other clues
    if (data.headers) {
      const hostingProviders = [
        { pattern: /x-goog-/i, name: "Google Cloud" },
        { pattern: /x-amz-/i, name: "Amazon Web Services" },
        { pattern: /x-azure-/i, name: "Microsoft Azure" },
        { pattern: /x-served-by: cache-.+\.cloudfront\.net/i, name: "AWS CloudFront" },
        { pattern: /x-github-request/i, name: "GitHub Pages" },
        { pattern: /x-vercel-/i, name: "Vercel" },
        { pattern: /x-netlify-/i, name: "Netlify" },
        { pattern: /x-heroku-/i, name: "Heroku" },
        { pattern: /x-powered-by: Express/i, name: "Node.js (Express)" },
        { pattern: /x-powered-by: PHP/i, name: "PHP" },
        { pattern: /x-powered-by: ASP\.NET/i, name: "ASP.NET" },
        { pattern: /x-drupal-/i, name: "Drupal" },
        { pattern: /x-wordpress-/i, name: "WordPress" },
        { pattern: /cloudflare/i, name: "Cloudflare" },
        { pattern: /fastly/i, name: "Fastly" },
        { pattern: /akamai/i, name: "Akamai" },
      ]

      // Check headers for hosting provider clues
      for (const [header, value] of Object.entries(data.headers)) {
        for (const provider of hostingProviders) {
          if (provider.pattern.test(header) || provider.pattern.test(value)) {
            hostingFound = true
            const hostingItem = document.createElement("div")
            hostingItem.className = "tech-item"
            hostingItem.innerHTML = `
              <div class="item-name">Provider</div>
              <div class="item-value">${provider.name}</div>
            `
            hostingInfoEl.appendChild(hostingItem)
            break
          }
        }
        if (hostingFound) break
      }
    }

    // Check for CDN
    if (data.technologies) {
      const cdn = data.technologies.find((tech) => tech.name === "CDN")
      if (cdn) {
        hostingFound = true
        const cdnItem = document.createElement("div")
        cdnItem.className = "tech-item"
        cdnItem.innerHTML = `
          <div class="item-name">CDN</div>
          <div class="item-value">${cdn.value}</div>
        `
        hostingInfoEl.appendChild(cdnItem)
      }
    }

    if (!hostingFound) {
      hostingInfoEl.innerHTML = "<div class='placeholder'>No hosting information detected</div>"
    }
  }

  // Function to update IP information
  function updateIpInfo(data) {
    const ipInfoEl = document.getElementById("ip-info")

    if (data.dnsRecords && data.dnsRecords.a && data.dnsRecords.a.length > 0) {
      ipInfoEl.innerHTML = ""

      // Display IP address
      const ipItem = document.createElement("div")
      ipItem.className = "tech-item"
      ipItem.innerHTML = `
        <div class="item-name">IP Address</div>
        <div class="item-value">${data.dnsRecords.a[0]}</div>
      `
      ipInfoEl.appendChild(ipItem)

      // If we have IP geolocation data
      if (data.ipInfo) {
        // Add location
        if (data.ipInfo.location) {
          const locationItem = document.createElement("div")
          locationItem.className = "tech-item"
          locationItem.innerHTML = `
            <div class="item-name">Location</div>
            <div class="item-value">${data.ipInfo.location}</div>
          `
          ipInfoEl.appendChild(locationItem)
        }

        // Add ISP
        if (data.ipInfo.isp) {
          const ispItem = document.createElement("div")
          ispItem.className = "tech-item"
          ispItem.innerHTML = `
            <div class="item-name">ISP</div>
            <div class="item-value">${data.ipInfo.isp}</div>
          `
          ipInfoEl.appendChild(ispItem)
        }
      }
    } else {
      ipInfoEl.innerHTML = "<div class='placeholder'>No IP information available</div>"
    }
  }

  // Function to update security headers
  function updateSecurityHeaders(data) {
    const securityHeadersEl = document.getElementById("security-headers")
    securityHeadersEl.innerHTML = ""

    // Check for common security headers
    const securityHeaders = [
      { name: "Content-Security-Policy", header: "content-security-policy", importance: "high" },
      { name: "X-XSS-Protection", header: "x-xss-protection", importance: "medium" },
      { name: "X-Frame-Options", header: "x-frame-options", importance: "high" },
      { name: "X-Content-Type-Options", header: "x-content-type-options", importance: "medium" },
      { name: "Strict-Transport-Security", header: "strict-transport-security", importance: "high" },
      { name: "Referrer-Policy", header: "referrer-policy", importance: "medium" },
      { name: "Feature-Policy", header: "feature-policy", importance: "low" },
      { name: "Permissions-Policy", header: "permissions-policy", importance: "low" },
    ]

    let securityHeadersFound = false

    securityHeaders.forEach((header) => {
      if (data.headers && data.headers[header.header]) {
        securityHeadersFound = true
        const headerItem = document.createElement("div")
        headerItem.className = "header-item"

        let statusClass = "status-good"

        // Check for weak configurations
        if (header.header === "x-xss-protection" && data.headers[header.header] === "0") {
          statusClass = "status-bad"
        }

        headerItem.innerHTML = `
          <div class="item-name">${header.name}</div>
          <div class="item-value">
            <span class="security-status ${statusClass}">${data.headers[header.header]}</span>
          </div>
        `
        securityHeadersEl.appendChild(headerItem)
      } else if (header.importance === "high") {
        // Show missing important headers
        securityHeadersFound = true
        const headerItem = document.createElement("div")
        headerItem.className = "header-item"
        headerItem.innerHTML = `
          <div class="item-name">${header.name}</div>
          <div class="item-value">
            <span class="security-status status-bad">Missing</span>
          </div>
        `
        securityHeadersEl.appendChild(headerItem)
      }
    })

    if (!securityHeadersFound) {
      securityHeadersEl.innerHTML = "<div class='placeholder'>No security headers detected</div>"
    }
  }

  // Function to update SSL/TLS information
  function updateSslInfo(data) {
    const sslInfoEl = document.getElementById("ssl-info")
    sslInfoEl.innerHTML = ""

    // Check if HTTPS is used
    const httpsItem = document.createElement("div")
    httpsItem.className = "tech-item"

    if (data.url.startsWith("https://")) {
      httpsItem.innerHTML = `
        <div class="item-name">HTTPS</div>
        <div class="item-value"><span class="security-status status-good">Enabled</span></div>
      `
    } else {
      httpsItem.innerHTML = `
        <div class="item-name">HTTPS</div>
        <div class="item-value"><span class="security-status status-bad">Disabled</span></div>
      `
    }

    sslInfoEl.appendChild(httpsItem)

    // Check for HSTS
    if (data.headers && data.headers["strict-transport-security"]) {
      const hstsItem = document.createElement("div")
      hstsItem.className = "tech-item"
      hstsItem.innerHTML = `
        <div class="item-name">HSTS</div>
        <div class="item-value"><span class="security-status status-good">Enabled</span></div>
      `
      sslInfoEl.appendChild(hstsItem)
    } else if (data.url.startsWith("https://")) {
      const hstsItem = document.createElement("div")
      hstsItem.className = "tech-item"
      hstsItem.innerHTML = `
        <div class="item-name">HSTS</div>
        <div class="item-value"><span class="security-status status-warning">Missing</span></div>
      `
      sslInfoEl.appendChild(hstsItem)
    }

    // If we have SSL certificate info
    if (data.sslInfo) {
      // Add issuer
      if (data.sslInfo.issuer) {
        const issuerItem = document.createElement("div")
        issuerItem.className = "tech-item"
        issuerItem.innerHTML = `
          <div class="item-name">Issuer</div>
          <div class="item-value">${data.sslInfo.issuer}</div>
        `
        sslInfoEl.appendChild(issuerItem)
      }

      // Add valid from/to
      if (data.sslInfo.validFrom && data.sslInfo.validTo) {
        const validityItem = document.createElement("div")
        validityItem.className = "tech-item"
        validityItem.innerHTML = `
          <div class="item-name">Validity</div>
          <div class="item-value">From: ${data.sslInfo.validFrom}<br>To: ${data.sslInfo.validTo}</div>
        `
        sslInfoEl.appendChild(validityItem)
      }
    }
  }

  // Function to update cookie security
  function updateCookieSecurity(data) {
    const cookieSecurityEl = document.getElementById("cookie-security")

    if (data.cookies && data.cookies.length > 0) {
      cookieSecurityEl.innerHTML = ""

      data.cookies.forEach((cookie) => {
        const cookieItem = document.createElement("div")
        cookieItem.className = "tech-item"

        const secureStatus = cookie.secure
          ? '<span class="security-status status-good">Yes</span>'
          : '<span class="security-status status-bad">No</span>'

        const httpOnlyStatus = cookie.httpOnly
          ? '<span class="security-status status-good">Yes</span>'
          : '<span class="security-status status-warning">No</span>'

        cookieItem.innerHTML = `
          <div class="item-name">${cookie.name}</div>
          <div class="item-value">
            Secure: ${secureStatus}<br>
            HttpOnly: ${httpOnlyStatus}<br>
            SameSite: ${cookie.sameSite || "Not set"}
          </div>
        `
        cookieSecurityEl.appendChild(cookieItem)
      })
    } else {
      cookieSecurityEl.innerHTML = "<div class='placeholder'>No cookies detected</div>"
    }
  }

  // Function to update potential vulnerabilities
  function updateVulnerabilities(data) {
    const vulnerabilitiesEl = document.getElementById("vulnerabilities")
    vulnerabilitiesEl.innerHTML = ""

    const vulnerabilities = []

    // Check for missing security headers
    const criticalHeaders = [
      { name: "Content-Security-Policy", header: "content-security-policy" },
      { name: "X-Frame-Options", header: "x-frame-options" },
      { name: "Strict-Transport-Security", header: "strict-transport-security" },
    ]

    criticalHeaders.forEach((header) => {
      if (!data.headers || !data.headers[header.header]) {
        vulnerabilities.push({
          name: `Missing ${header.name}`,
          description: `The ${header.name} header is not set, which could expose the site to various attacks.`,
          severity: "medium",
        })
      }
    })

    // Check for HTTP instead of HTTPS
    if (!data.url.startsWith("https://")) {
      vulnerabilities.push({
        name: "HTTP Instead of HTTPS",
        description: "The site is using HTTP instead of HTTPS, which means data is transmitted in clear text.",
        severity: "high",
      })
    }

    // Check for outdated server software
    if (data.headers && data.headers["server"]) {
      const serverVersion = data.headers["server"]
      const outdatedServers = [
        { pattern: /apache\/2\.[0-3]\./i, name: "Apache < 2.4" },
        { pattern: /nginx\/1\.[0-9]\./i, name: "Nginx < 1.10" },
        { pattern: /microsoft-iis\/[1-7]\./i, name: "IIS < 8.0" },
      ]

      outdatedServers.forEach((server) => {
        if (server.pattern.test(serverVersion)) {
          vulnerabilities.push({
            name: "Outdated Server Software",
            description: `The server is running ${server.name}, which may contain known vulnerabilities.`,
            severity: "medium",
          })
        }
      })
    }

    // Display vulnerabilities
    if (vulnerabilities.length > 0) {
      vulnerabilities.forEach((vuln) => {
        const vulnItem = document.createElement("div")
        vulnItem.className = "tech-item"

        let severityClass = "status-warning"
        if (vuln.severity === "high") {
          severityClass = "status-bad"
        } else if (vuln.severity === "low") {
          severityClass = "status-good"
        }

        vulnItem.innerHTML = `
          <div class="item-name">${vuln.name}</div>
          <div class="item-value">
            <span class="security-status ${severityClass}">${vuln.severity}</span>
            <p>${vuln.description}</p>
          </div>
        `
        vulnerabilitiesEl.appendChild(vulnItem)
      })
    } else {
      vulnerabilitiesEl.innerHTML = "<div class='placeholder'>No obvious vulnerabilities detected</div>"
    }
  }

  // Function to update HTML structure
  function updateHtmlStructure(data) {
    const htmlStructureEl = document.getElementById("html-structure")

    if (data.htmlStructure) {
      htmlStructureEl.innerHTML = `<div class="tree-view">${data.htmlStructure}</div>`
    } else {
      htmlStructureEl.innerHTML = "<div class='placeholder'>HTML structure analysis not available</div>"
    }
  }

  // Function to update JavaScript files
  function updateJsFiles(data) {
    const jsFilesEl = document.getElementById("js-files")

    if (data.scripts && data.scripts.length > 0) {
      jsFilesEl.innerHTML = ""

      data.scripts.forEach((script, index) => {
        const scriptItem = document.createElement("div")
        scriptItem.className = "resource-item"

        // Extract filename from URL
        const filename = script.split("/").pop() || `script-${index + 1}`

        scriptItem.innerHTML = `
          <div class="item-name">${filename}</div>
          <div class="item-value">
            <a href="#" data-url="${script}" class="internal-link">${script}</a>
          </div>
        `
        jsFilesEl.appendChild(scriptItem)
      })

      // Add event listeners for internal links
      jsFilesEl.querySelectorAll(".internal-link").forEach((link) => {
        link.addEventListener("click", (e) => {
          e.preventDefault()
          const url = e.target.getAttribute("data-url")
          ipcRenderer.send("open-url-in-webview", url)
        })
      })
    } else {
      jsFilesEl.innerHTML = "<div class='placeholder'>No JavaScript files detected</div>"
    }
  }

  // Function to update CSS files
  function updateCssFiles(data) {
    const cssFilesEl = document.getElementById("css-files")

    if (data.cssFiles && data.cssFiles.length > 0) {
      cssFilesEl.innerHTML = ""

      data.cssFiles.forEach((css, index) => {
        const cssItem = document.createElement("div")
        cssItem.className = "resource-item"

        // Extract filename from URL
        const filename = css.split("/").pop() || `style-${index + 1}`

        cssItem.innerHTML = `
          <div class="item-name">${filename}</div>
          <div class="item-value">
            <a href="#" data-url="${css}" class="internal-link">${css}</a>
          </div>
        `
        cssFilesEl.appendChild(cssItem)
      })

      // Add event listeners for internal links
      cssFilesEl.querySelectorAll(".internal-link").forEach((link) => {
        link.addEventListener("click", (e) => {
          e.preventDefault()
          const url = e.target.getAttribute("data-url")
          ipcRenderer.send("open-url-in-webview", url)
        })
      })
    } else {
      cssFilesEl.innerHTML = "<div class='placeholder'>No CSS files detected</div>"
    }
  }

  // Function to update images
  function updateImages(data) {
    const imagesEl = document.getElementById("images")

    if (data.images && data.images.length > 0) {
      imagesEl.innerHTML = '<div class="image-gallery"></div>'
      const gallery = imagesEl.querySelector(".image-gallery")

      data.images.slice(0, 20).forEach((image, index) => {
        const imageItem = document.createElement("div")
        imageItem.className = "image-item"

        // Extract filename from URL
        const filename = image.split("/").pop() || `image-${index + 1}`

        imageItem.innerHTML = `
          <img src="${image}" alt="${filename}" onerror="this.src='data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22100%22%20height%3D%22100%22%3E%3Crect%20fill%3D%22%23ccc%22%20width%3D%22100%22%20height%3D%22100%22%2F%3E%3Cpath%20fill%3D%22%23fff%22%20d%3D%22M36.5%2C22.5h27v55h-27z%22%2F%3E%3C%2Fsvg%3E';" />
          <div class="image-info">${filename}</div>
        `

        // Add click event to open image in internal browser
        imageItem.addEventListener("click", () => {
          ipcRenderer.send("open-url-in-webview", image)
        })

        gallery.appendChild(imageItem)
      })

      if (data.images.length > 20) {
        const moreInfo = document.createElement("div")
        moreInfo.className = "more-info"
        moreInfo.textContent = `And ${data.images.length - 20} more images...`
        imagesEl.appendChild(moreInfo)
      }
    } else {
      imagesEl.innerHTML = "<div class='placeholder'>No images detected</div>"
    }
  }

  // Function to update forms
  function updateForms(data) {
    const formsInfoEl = document.getElementById("forms-info")

    if (data.forms && data.forms.length > 0) {
      formsInfoEl.innerHTML = ""

      data.forms.forEach((form, index) => {
        const formItem = document.createElement("div")
        formItem.className = "form-item"

        // Determine form type
        let formType = "Unknown"
        if (form.action && form.action.includes("login")) {
          formType = "Login Form"
        } else if (form.action && form.action.includes("register")) {
          formType = "Registration Form"
        } else if (form.action && form.action.includes("search")) {
          formType = "Search Form"
        } else if (form.action && form.action.includes("contact")) {
          formType = "Contact Form"
        } else {
          formType = `Form ${index + 1}`
        }

        formItem.innerHTML = `
          <div class="item-name">${formType}</div>
          <div class="item-value">
            <div>Action: ${form.action || "Not specified"}</div>
            <div>Method: ${form.method || "GET"}</div>
          </div>
        `
        formsInfoEl.appendChild(formItem)
      })
    } else {
      formsInfoEl.innerHTML = "<div class='placeholder'>No forms detected</div>"
    }
  }

  // Function to update external links
  function updateExternalLinks(data) {
    const externalLinksEl = document.getElementById("external-links")

    if (data.links && data.links.length > 0) {
      externalLinksEl.innerHTML = ""

      // Filter external links
      const domain = new URL(data.url).hostname
      const externalLinks = data.links.filter((link) => {
        try {
          const linkDomain = new URL(link).hostname
          return linkDomain !== domain
        } catch (e) {
          return false
        }
      })

      if (externalLinks.length > 0) {
        externalLinks.forEach((link) => {
          const linkItem = document.createElement("div")
          linkItem.className = "link-item"
          linkItem.innerHTML = `
            <div class="link-icon"><i class="fas fa-external-link-alt"></i></div>
            <div class="link-url"><a href="#" data-url="${link}" class="internal-link">${link}</a></div>
          `
          externalLinksEl.appendChild(linkItem)
        })

        // Add event listeners for internal links
        externalLinksEl.querySelectorAll(".internal-link").forEach((link) => {
          link.addEventListener("click", (e) => {
            e.preventDefault()
            const url = e.target.getAttribute("data-url")
            ipcRenderer.send("open-url-in-webview", url)
          })
        })
      } else {
        externalLinksEl.innerHTML = "<div class='placeholder'>No external links detected</div>"
      }
    } else {
      externalLinksEl.innerHTML = "<div class='placeholder'>No external links detected</div>"
    }
  }

  // Function to update domain registration
  function updateDomainRegistration(data) {
    const domainRegistrationEl = document.getElementById("domain-registration")

    if (data.domainInfo && !data.domainInfo.error) {
      domainRegistrationEl.innerHTML = ""

      // Add registrar
      if (data.domainInfo.registrar) {
        const registrarItem = document.createElement("div")
        registrarItem.className = "whois-item"
        registrarItem.innerHTML = `
          <div class="item-name">Registrar</div>
          <div class="item-value">${data.domainInfo.registrar}</div>
        `
        domainRegistrationEl.appendChild(registrarItem)
      }

      // Add creation date
      if (data.domainInfo.creationDate) {
        const creationItem = document.createElement("div")
        creationItem.className = "whois-item"
        creationItem.innerHTML = `
          <div class="item-name">Created</div>
          <div class="item-value">${data.domainInfo.creationDate}</div>
        `
        domainRegistrationEl.appendChild(creationItem)
      }

      // Add expiration date
      if (data.domainInfo.expirationDate) {
        const expirationItem = document.createElement("div")
        expirationItem.className = "whois-item"
        expirationItem.innerHTML = `
          <div class="item-name">Expires</div>
          <div class="item-value">${data.domainInfo.expirationDate}</div>
        `
        domainRegistrationEl.appendChild(expirationItem)
      }

      // Add updated date
      if (data.domainInfo.updatedDate) {
        const updatedItem = document.createElement("div")
        updatedItem.className = "whois-item"
        updatedItem.innerHTML = `
          <div class="item-name">Updated</div>
          <div class="item-value">${data.domainInfo.updatedDate}</div>
        `
        domainRegistrationEl.appendChild(updatedItem)
      }
    } else {
      domainRegistrationEl.innerHTML = "<div class='placeholder'>No domain registration information available</div>"
    }
  }

  // Function to update WHOIS information
  function updateWhoisInfo(data) {
    const whoisInfoEl = document.getElementById("whois-info")

    if (data.domainInfo && data.domainInfo.whois) {
      whoisInfoEl.innerHTML = `<pre class="code-block">${data.domainInfo.whois}</pre>`
    } else {
      whoisInfoEl.innerHTML = "<div class='placeholder'>No WHOIS information available</div>"
    }
  }

  // Function to update domain history
  function updateDomainHistory(data) {
    const domainHistoryEl = document.getElementById("domain-history")

    if (data.domainInfo && data.domainInfo.history) {
      domainHistoryEl.innerHTML = ""

      data.domainInfo.history.forEach((entry) => {
        const historyItem = document.createElement("div")
        historyItem.className = "whois-item"
        historyItem.innerHTML = `
          <div class="item-name">${entry.date}</div>
          <div class="item-value">${entry.event}</div>
        `
        domainHistoryEl.appendChild(historyItem)
      })
    } else {
      domainHistoryEl.innerHTML = "<div class='placeholder'>No domain history available</div>"
    }
  }

  // Helper function to show notifications
  function showNotification(message, type = "info") {
    let notificationEl = document.querySelector(".notification")

    if (!notificationEl) {
      notificationEl = document.createElement("div")
      notificationEl.className = "notification"
      document.body.appendChild(notificationEl)
    }

    notificationEl.textContent = message
    notificationEl.className = `notification ${type}`

    // Show notification
    notificationEl.style.opacity = "1"

    // Hide after 3 seconds
    setTimeout(() => {
      notificationEl.style.opacity = "0"
      setTimeout(() => {
        notificationEl.remove()
      }, 500)
    }, 3000)
  }
})

