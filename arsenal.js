const { ipcRenderer } = require("electron")

document.addEventListener("DOMContentLoaded", () => {
  // Setup particles
  setupParticles()

  // Window controls - using both class and ID selectors for compatibility
  const minimizeBtn = document.getElementById("minimize-btn")
  minimizeBtn.addEventListener("click", () => {
    console.log("Minimize button clicked")
    addClickEffect(minimizeBtn)
    ipcRenderer.send("minimize-window")
  })

  const closeBtn = document.getElementById("close-btn")
  closeBtn.addEventListener("click", () => {
    console.log("Close button clicked")
    addClickEffect(closeBtn)
    ipcRenderer.send("close-window")
  })

  // Also add the original selectors as a fallback
  document.querySelector(".minimize").addEventListener("click", () => {
    console.log("Minimize button clicked (class selector)")
    addClickEffect(document.querySelector(".minimize"))
    ipcRenderer.send("minimize-window")
  })

  document.querySelector(".close").addEventListener("click", () => {
    console.log("Close button clicked (class selector)")
    addClickEffect(document.querySelector(".close"))
    ipcRenderer.send("close-window")
  })

  // Proxy toggle
  const proxyToggle = document.getElementById("proxyToggle")
  if (proxyToggle && proxyToggle.tagName === "INPUT") {
    proxyToggle.addEventListener("change", (e) => {
      console.log("Proxy toggle changed:", e.target.checked)
      ipcRenderer.send("toggle-proxy", e.target.checked)
    })
  }

  // Setup tool cards with enhanced interactions
  setupToolCards()

  // Setup tooltips
  setupTooltips()

  // Log that the app is ready
  console.log("Arsenal UI initialized")
  updateStatusMessage("Arsenal ready")
})

// Setup particles animation
function setupParticles() {
  const container = document.getElementById("particles-container")
  if (!container) return

  const particleCount = 20

  for (let i = 0; i < particleCount; i++) {
    const particle = document.createElement("div")
    particle.className = "particle"

    // Random size between 2px and 6px
    const size = Math.random() * 4 + 2
    particle.style.width = `${size}px`
    particle.style.height = `${size}px`

    // Random position
    particle.style.left = `${Math.random() * 100}%`
    particle.style.top = `${Math.random() * 100}%`

    // Random opacity
    particle.style.opacity = `${Math.random() * 0.3 + 0.1}`

    // Random animation duration
    const duration = Math.random() * 10 + 10
    particle.style.animationDuration = `${duration}s`

    // Random animation delay
    particle.style.animationDelay = `${Math.random() * 5}s`

    container.appendChild(particle)
  }
}

// Setup tool cards with enhanced interactions
function setupToolCards() {
  const toolCards = document.querySelectorAll(".tool-card")

  toolCards.forEach((card) => {
    // Add entrance animation
    card.style.opacity = "0"
    card.style.transform = "translateY(20px)"

    setTimeout(
      () => {
        card.style.transition = "opacity 0.5s ease, transform 0.5s ease"
        card.style.opacity = "1"
        card.style.transform = "translateY(0)"
      },
      100 + Array.from(toolCards).indexOf(card) * 50,
    ) // Staggered animation

    // Add click effect
    card.addEventListener("click", (e) => {
      // Don't trigger if clicking on a toggle switch
      if (e.target.tagName === "INPUT" || e.target.classList.contains("slider")) {
        return
      }

      addClickEffect(card)

      // Update status message based on the tool
      const toolName = card.querySelector(".tool-name").textContent
      updateStatusMessage(`Launching ${toolName}...`)

      // Add temporary active state
      card.classList.add("active")
      setTimeout(() => {
        card.classList.remove("active")
      }, 1000)
    })

    // Handle specific tool clicks
    setupToolCardHandlers(card)
  })
}

// Setup specific tool card handlers
function setupToolCardHandlers(card) {
  const id = card.id

  if (id === "proxy-toggle") {
    card.addEventListener("click", () => {
      console.log("Requesting to open mitmweb proxy window...")
      ipcRenderer.send("open-mitmweb-proxy")
    })
  } else if (id === "web-recon-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening web recon window")
      ipcRenderer.send("open-web-recon")
    })
  } else if (id === "bruteforcer-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening bruteforcer window")
      ipcRenderer.send("open-bruteforcer")
    })
  } else if (id === "nmap-scanner-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening nmap scanner window")
      ipcRenderer.send("open-nmap-scanner")
    })
  } else if (id === "injection-tester-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening injection tester window")
      ipcRenderer.send("open-injection-tester")
    })
  } else if (id === "spiders-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening Spiders window")
      ipcRenderer.send("open-spiders")
    })
  } else if (id === "paramhunter-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening ParamHunter window")
      ipcRenderer.send("open-paramhunter")
    })
  } else if (id === "burpsuite-tool") {
    card.addEventListener("click", () => {
      console.log("Opening Burp Suite")
      window.electronAPI?.openBurpSuite?.() || require("electron").ipcRenderer.send("open-burpsuite")
    })
  } else if (id === "illusion-toggle") {
    card.addEventListener("click", () => {
      console.log("Opening Illusion tool window...")
      ipcRenderer.send("open-illusion-tool")
    })
  }
}

// Add click effect to elements
function addClickEffect(element) {
  element.style.transform = "scale(0.95)"
  setTimeout(() => {
    element.style.transform = ""
  }, 150)
}

// Update status message
function updateStatusMessage(message) {
  const statusMessage = document.getElementById("status-message")
  if (statusMessage) {
    statusMessage.textContent = message
  }
}

// Setup tooltips
function setupTooltips() {
  const tooltip = document.getElementById("tooltip")
  if (!tooltip) return

  const toolCards = document.querySelectorAll(".tool-card")

  toolCards.forEach((card) => {
    const toolName = card.querySelector(".tool-name").textContent
    const toolDescription = card.querySelector(".tool-description").textContent

    // Create enhanced tooltip content
    const tooltipContent = `
      <strong>${toolName}</strong><br>
      ${toolDescription}<br>
      <span style="color: var(--primary); font-size: 10px;">Click to launch</span>
    `

    card.addEventListener("mouseenter", (e) => {
      tooltip.innerHTML = tooltipContent
      tooltip.classList.add("visible")

      // Position the tooltip
      positionTooltip(e, tooltip)
    })

    card.addEventListener("mousemove", (e) => {
      // Update tooltip position on mouse move
      positionTooltip(e, tooltip)
    })

    card.addEventListener("mouseleave", () => {
      tooltip.classList.remove("visible")
    })
  })
}

// Position tooltip near the cursor
function positionTooltip(e, tooltip) {
  const x = e.clientX + 15
  const y = e.clientY + 15

  // Check if tooltip would go off-screen
  const tooltipRect = tooltip.getBoundingClientRect()
  const rightEdge = x + tooltipRect.width
  const bottomEdge = y + tooltipRect.height

  // Adjust position if needed
  const adjustedX = rightEdge > window.innerWidth ? window.innerWidth - tooltipRect.width - 10 : x
  const adjustedY = bottomEdge > window.innerHeight ? window.innerHeight - tooltipRect.height - 10 : y

  tooltip.style.left = `${adjustedX}px`
  tooltip.style.top = `${adjustedY}px`
}

// Listen for IPC messages from main process
ipcRenderer.on("tool-status-update", (event, data) => {
  const { toolId, status, message } = data

  // Find the tool card
  const toolCard = document.getElementById(toolId)
  if (!toolCard) return

  // Update tool status
  if (status === "active") {
    toolCard.classList.add("active")
  } else if (status === "inactive") {
    toolCard.classList.remove("active")
  } else if (status === "disabled") {
    toolCard.classList.add("disabled")
  } else if (status === "enabled") {
    toolCard.classList.remove("disabled")
  }

  // Update status message if provided
  if (message) {
    updateStatusMessage(message)
  }
})

// Add a global keyboard shortcut handler
document.addEventListener("keydown", (e) => {
  // Ctrl+F to focus search (if we add search later)
  if (e.ctrlKey && e.key === "f") {
    const searchInput = document.getElementById("search-input")
    if (searchInput) {
      e.preventDefault()
      searchInput.focus()
    }
  }

  // Escape to close any active dialogs
  if (e.key === "Escape") {
    // Implementation for closing dialogs would go here
  }
})
