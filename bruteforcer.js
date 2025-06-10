const { ipcRenderer, shell } = require("electron")
const fs = require("fs")
const path = require("path")
const { URL } = require("url")
const http = require("http")
const https = require("https")
const { networkInterfaces } = require("os")

// Add these variables to the top of the file after other variable declarations
let progressBar
let progressLabel
let currentWordElement
let totalWordsElement
let progressContainer

// DOM elements
let urlInput, wordlistInput, extensionsInput, startBtn, stopBtn, resultsContainer
const isBruteforcing = false
const shouldStop = false

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

  // DOM Elements
  const targetUrlInput = document.getElementById("target-url")
  const targetTypeSelect = document.getElementById("target-type")
  const wordlistSelect = document.getElementById("wordlist-select")
  const refreshWordlistsBtn = document.getElementById("refresh-wordlists")
  const threadsInput = document.getElementById("threads")
  const timeoutInput = document.getElementById("timeout")
  const extensionsInput = document.getElementById("extensions")
  const statusCodesInput = document.getElementById("status-codes")
  const recursiveCheckbox = document.getElementById("recursive")
  const followRedirectsCheckbox = document.getElementById("follow-redirects")
  const caseSensitiveCheckbox = document.getElementById("case-sensitive")
  const showProgressCheckbox = document.getElementById("show-progress")
  const autoSaveCheckbox = document.getElementById("auto-save")
  const dnsResolutionCheckbox = document.getElementById("dns-resolution")
  const startBtn = document.getElementById("start-btn")
  const stopBtn = document.getElementById("stop-btn")
  const clearBtn = document.getElementById("clear-btn")
  const exportBtn = document.getElementById("export-btn")
  const filterResultsInput = document.getElementById("filter-results")
  const filterStatusSelect = document.getElementById("filter-status")
  const resultsBody = document.getElementById("results-body")
  const progressText = document.getElementById("progress-text")
  const totalRequestsEl = document.getElementById("total-requests")
  const elapsedTimeEl = document.getElementById("elapsed-time")
  const requestsPerSecondEl = document.getElementById("requests-per-second")
  const foundItemsEl = document.getElementById("found-items")
  const errorCountEl = document.getElementById("error-count")
  const avgResponseTimeEl = document.getElementById("avg-response-time")
  const statusBarsEl = document.getElementById("status-bars")
  const logContentEl = document.getElementById("log-content")

  // Add progress bar elements
  const progressContainer = document.createElement("div")
  progressContainer.className = "progress-container"
  progressContainer.style.display = "none"
  progressContainer.innerHTML = `
    <div class="progress-info">
      <span>Testing word: <span id="current-word">-</span></span>
      <span>Progress: <span id="progress-count">0</span>/<span id="total-words">0</span></span>
    </div>
    <div class="progress-bar-container">
      <div id="progress-bar" class="progress-bar"></div>
    </div>
  `

  // Insert progress container before the results container
  const resultsContainer = document.getElementById("results-container")
  if (resultsContainer && resultsContainer.parentNode) {
    resultsContainer.parentNode.insertBefore(progressContainer, resultsContainer)
  }

  // Get progress elements
  const progressBar = document.getElementById("progress-bar")
  const currentWordElement = document.getElementById("current-word")
  const totalWordsElement = document.getElementById("total-words")
  const progressLabel = document.getElementById("progress-count")

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

  // State variables
  let isRunning = false
  let wordlist = []
  let currentIndex = 0
  let startTime = 0
  let elapsedTimeInterval = null
  let results = []
  let statusCounts = {}
  let totalRequests = 0
  let successfulRequests = 0
  let errorRequests = 0
  let totalResponseTime = 0
  let activeRequests = 0
  let abortController = null
  let wordlistsDirectory = null

  // Load wordlists
  loadWordlists()

  // Event listeners
  refreshWordlistsBtn.addEventListener("click", loadWordlists)
  startBtn.addEventListener("click", startBruteforce)
  stopBtn.addEventListener("click", stopBruteforce)
  clearBtn.addEventListener("click", clearResults)
  exportBtn.addEventListener("click", exportResults)
  filterResultsInput.addEventListener("input", filterResults)
  filterStatusSelect.addEventListener("change", filterResults)

  // Function to find wordlists directory
  function findWordlistsDirectory() {
    const possiblePaths = [
      path.join(process.cwd(), "wordlists"),
      path.join(__dirname, "wordlists"),
      path.join(path.dirname(process.execPath), "wordlists"),
      path.join(path.dirname(path.dirname(process.execPath)), "wordlists"),
      path.join(process.env.APPDATA || process.env.HOME || process.cwd(), "wordlists"),
      path.join(process.env.USERPROFILE || process.env.HOME || process.cwd(), "wordlists"),
      path.join(process.env.LOCALAPPDATA || process.env.HOME || process.cwd(), "wordlists"),
    ]

    // Add all parent directories up to root
    let currentDir = process.cwd()
    while (currentDir !== path.parse(currentDir).root) {
      possiblePaths.push(path.join(currentDir, "wordlists"))
      currentDir = path.dirname(currentDir)
    }

    // Check each path
    for (const dirPath of possiblePaths) {
      try {
        if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
          return dirPath
        }
      } catch (err) {
        // Ignore errors
      }
    }

    // If no directory found, create one in the current directory
    const defaultDir = path.join(process.cwd(), "wordlists")
    try {
      if (!fs.existsSync(defaultDir)) {
        fs.mkdirSync(defaultDir, { recursive: true })
      }
      return defaultDir
    } catch (err) {
      console.error("Failed to create wordlists directory:", err)
      return null
    }
  }

  // Function to create default wordlists
  function createDefaultWordlists(directory) {
    if (!directory) return false

    const wordlists = [
      {
        name: "common-subdomains.txt",
        content: [
          "www",
          "mail",
          "remote",
          "blog",
          "webmail",
          "server",
          "ns1",
          "ns2",
          "smtp",
          "secure",
          "vpn",
          "shop",
          "ftp",
          "ssh",
          "admin",
          "mx",
          "pop",
          "imap",
          "forum",
          "portal",
          "dev",
          "test",
          "staging",
          "api",
          "cdn",
          "app",
          "auth",
          "beta",
          "gateway",
          "intranet",
          "internal",
          "corp",
          "backup",
          "sql",
          "db",
          "demo",
          "support",
          "help",
          "cloud",
          "mobile",
          "chat",
          "m",
          "status",
          "monitor",
          "analytics",
          "stats",
          "ads",
          "media",
          "video",
          "img",
          "images",
          "files",
          "docs",
          "web",
          "host",
          "hosting",
          "login",
          "signup",
          "register",
          "download",
          "upload",
          "static",
          "cms",
          "crm",
          "erp",
          "hr",
          "billing",
          "pay",
          "payment",
          "store",
          "shop",
          "cart",
          "checkout",
          "order",
          "wiki",
          "kb",
          "knowledge",
          "help",
          "support",
          "ticket",
          "client",
          "partner",
          "partners",
          "reseller",
          "affiliates",
          "affiliate",
          "marketing",
          "social",
          "community",
          "forum",
          "forums",
          "blog",
          "blogs",
          "news",
          "events",
          "calendar",
          "jobs",
          "careers",
          "about",
          "contact",
          "feedback",
          "survey",
          "search",
          "find",
          "locate",
          "map",
          "maps",
          "directions",
          "locations",
          "store-locator",
          "office",
          "offices",
          "branch",
          "branches",
          "department",
          "departments",
          "team",
          "staff",
          "employee",
          "employees",
          "member",
          "members",
          "user",
          "users",
          "account",
          "accounts",
          "profile",
          "profiles",
          "dashboard",
          "panel",
          "control",
          "admin",
          "administrator",
          "manage",
          "management",
          "system",
          "systems",
          "network",
          "networks",
          "infrastructure",
          "security",
          "secure",
          "ssl",
          "vpn",
          "remote",
          "access",
          "connect",
          "connection",
          "status",
          "health",
          "monitor",
          "monitoring",
          "analytics",
          "report",
          "reports",
          "stats",
          "statistics",
          "metrics",
          "performance",
          "audit",
          "log",
          "logs",
          "error",
          "errors",
          "debug",
          "test",
          "testing",
          "beta",
          "alpha",
          "dev",
          "development",
          "stage",
          "staging",
          "prod",
          "production",
          "uat",
          "qa",
          "qc",
          "build",
          "ci",
          "jenkins",
          "git",
          "svn",
          "code",
          "source",
          "repo",
          "repository",
          "project",
          "projects",
          "task",
          "tasks",
          "issue",
          "issues",
          "bug",
          "bugs",
          "ticket",
          "tickets",
          "feature",
          "features",
          "request",
          "requests",
          "backlog",
          "sprint",
          "release",
          "version",
          "update",
          "updates",
          "patch",
          "patches",
          "hotfix",
          "fix",
          "changelog",
          "history",
          "archive",
          "old",
          "new",
          "latest",
          "current",
          "previous",
          "next",
          "future",
          "roadmap",
          "plan",
          "planning",
          "strategy",
          "vision",
          "mission",
          "goals",
          "objective",
          "objectives",
          "target",
          "targets",
          "kpi",
          "kpis",
          "metric",
          "metrics",
          "measure",
          "measures",
          "measurement",
          "measurements",
          "benchmark",
          "benchmarks",
          "standard",
          "standards",
          "policy",
          "policies",
          "procedure",
          "procedures",
          "process",
          "processes",
          "workflow",
          "workflows",
          "guide",
          "guides",
          "guideline",
          "guidelines",
          "manual",
          "manuals",
          "handbook",
          "reference",
          "references",
          "resource",
          "resources",
          "tool",
          "tools",
          "utility",
          "utilities",
          "app",
          "apps",
          "application",
          "applications",
          "program",
          "programs",
          "software",
          "service",
          "services",
          "solution",
          "solutions",
          "product",
          "products",
          "offering",
          "offerings",
          "package",
          "packages",
          "bundle",
          "bundles",
          "suite",
          "library",
          "libraries",
          "framework",
          "frameworks",
          "platform",
          "platforms",
          "infrastructure",
          "architecture",
          "design",
          "model",
          "models",
          "pattern",
          "patterns",
          "template",
          "templates",
          "example",
          "examples",
          "sample",
          "samples",
          "demo",
          "demos",
          "prototype",
          "prototypes",
          "concept",
          "concepts",
          "idea",
          "ideas",
          "innovation",
          "innovations",
          "research",
          "development",
          "rd",
          "lab",
          "labs",
          "laboratory",
          "laboratories",
          "experiment",
          "experiments",
          "trial",
          "trials",
          "pilot",
          "test",
          "tests",
          "testing",
          "validation",
          "verification",
          "audit",
          "review",
          "assessment",
          "evaluation",
          "analysis",
          "analytics",
          "insight",
          "insights",
          "intelligence",
          "data",
          "database",
          "databases",
          "db",
          "dbs",
          "warehouse",
          "warehouses",
          "lake",
          "lakes",
          "repository",
          "repositories",
          "storage",
          "store",
          "cache",
          "memory",
          "disk",
          "drive",
          "volume",
          "server",
          "servers",
          "host",
          "hosts",
          "node",
          "nodes",
          "cluster",
          "clusters",
          "farm",
          "grid",
          "cloud",
          "instance",
          "instances",
          "container",
          "containers",
          "pod",
          "pods",
          "vm",
          "vms",
          "virtual",
          "machine",
          "machines",
          "hardware",
          "device",
          "devices",
          "equipment",
          "asset",
          "assets",
          "inventory",
          "stock",
          "supply",
          "supplies",
          "resource",
          "resources",
          "capacity",
          "performance",
          "speed",
          "bandwidth",
          "throughput",
          "latency",
          "response",
          "time",
          "uptime",
          "downtime",
          "availability",
          "reliability",
          "stability",
          "scalability",
          "elasticity",
          "flexibility",
          "agility",
          "efficiency",
          "effectiveness",
          "productivity",
          "quality",
          "security",
          "safety",
          "compliance",
          "governance",
          "risk",
          "control",
          "management",
          "administration",
          "operation",
          "operations",
          "maintenance",
          "support",
          "service",
          "desk",
          "help",
          "assistance",
          "aid",
          "backup",
          "recovery",
          "restore",
          "archive",
          "retention",
          "disposal",
          "deletion",
          "purge",
          "clean",
          "clear",
          "reset",
          "restart",
          "reboot",
          "shutdown",
          "power",
          "energy",
          "cooling",
          "temperature",
          "climate",
          "environment",
          "facility",
          "facilities",
          "building",
          "buildings",
          "floor",
          "floors",
          "room",
          "rooms",
          "area",
          "areas",
          "zone",
          "zones",
          "sector",
          "sectors",
          "segment",
          "segments",
          "section",
          "sections",
          "part",
          "parts",
          "component",
          "components",
          "module",
          "modules",
          "unit",
          "units",
          "element",
          "elements",
          "item",
          "items",
          "object",
          "objects",
          "entity",
          "entities",
          "record",
          "records",
          "entry",
          "entries",
          "row",
          "rows",
          "column",
          "columns",
          "field",
          "fields",
          "attribute",
          "attributes",
          "property",
          "properties",
          "value",
          "values",
          "variable",
          "variables",
          "parameter",
          "parameters",
          "argument",
          "arguments",
          "option",
          "options",
          "setting",
          "settings",
          "configuration",
          "configurations",
          "preference",
          "preferences",
          "profile",
          "profiles",
          "account",
          "accounts",
          "user",
          "users",
          "member",
          "members",
          "customer",
          "customers",
          "client",
          "clients",
          "partner",
          "partners",
          "vendor",
          "vendors",
          "supplier",
          "suppliers",
          "provider",
          "providers",
          "contractor",
          "contractors",
          "consultant",
          "consultants",
          "advisor",
          "advisors",
          "expert",
          "experts",
          "specialist",
          "specialists",
          "professional",
          "professionals",
          "staff",
          "employee",
          "employees",
          "worker",
          "workers",
          "personnel",
          "team",
          "teams",
          "group",
          "groups",
          "department",
          "departments",
          "division",
          "divisions",
          "unit",
          "units",
          "branch",
          "branches",
          "office",
          "offices",
          "location",
          "locations",
          "site",
          "sites",
          "region",
          "regions",
          "zone",
          "zones",
          "area",
          "areas",
          "territory",
          "territories",
          "market",
          "markets",
          "segment",
          "segments",
          "sector",
          "sectors",
          "industry",
          "industries",
          "vertical",
          "verticals",
          "horizontal",
          "horizontals",
          "business",
          "businesses",
          "company",
          "companies",
          "corporation",
          "corporations",
          "enterprise",
          "enterprises",
          "organization",
          "organizations",
          "institution",
          "institutions",
          "agency",
          "agencies",
          "authority",
          "authorities",
          "bureau",
          "bureaus",
          "commission",
          "commissions",
          "committee",
          "committees",
          "council",
          "councils",
          "board",
          "boards",
          "panel",
          "panels",
          "forum",
          "forums",
          "assembly",
          "assemblies",
          "meeting",
          "meetings",
          "conference",
          "conferences",
          "convention",
          "conventions",
          "summit",
          "summits",
          "symposium",
          "symposiums",
          "seminar",
          "seminars",
          "workshop",
          "workshops",
          "class",
          "classes",
          "course",
          "courses",
          "training",
          "education",
          "learning",
          "development",
          "growth",
          "improvement",
          "enhancement",
          "upgrade",
          "update",
          "patch",
          "patches",
          "fix",
          "repair",
          "maintenance",
          "service",
          "support",
          "help",
          "assistance",
          "guidance",
          "direction",
          "instruction",
          "information",
          "data",
          "content",
          "material",
          "resource",
          "document",
          "file",
          "record",
          "entry",
          "item",
          "element",
          "component",
          "module",
          "unit",
          "part",
          "piece",
          "section",
          "segment",
          "fragment",
          "chunk",
          "block",
          "object",
          "entity",
          "instance",
          "occurrence",
          "event",
          "activity",
          "action",
          "task",
          "job",
          "work",
          "project",
          "program",
          "initiative",
          "effort",
          "endeavor",
          "venture",
          "undertaking",
          "operation",
          "mission",
          "campaign",
          "drive",
          "push",
          "movement",
          "trend",
          "wave",
          "cycle",
          "period",
          "phase",
          "stage",
          "step",
          "level",
          "tier",
          "layer",
          "rank",
          "grade",
          "class",
          "category",
          "type",
          "kind",
          "sort",
          "variety",
          "form",
          "version",
          "edition",
          "release",
          "build",
          "generation",
          "series",
          "line",
          "family",
          "group",
          "set",
          "collection",
          "compilation",
          "assembly",
          "bundle",
          "package",
          "kit",
          "suite",
          "system",
          "platform",
          "framework",
          "infrastructure",
          "architecture",
          "structure",
          "composition",
          "configuration",
          "arrangement",
          "organization",
          "format",
          "layout",
          "design",
          "pattern",
          "template",
          "model",
          "prototype",
          "sample",
          "example",
          "specimen",
          "case",
          "instance",
          "scenario",
          "situation",
          "condition",
          "state",
          "status",
          "mode",
          "manner",
          "way",
          "method",
          "technique",
          "approach",
          "strategy",
          "tactic",
          "plan",
          "scheme",
          "program",
          "agenda",
          "schedule",
          "timeline",
          "roadmap",
          "path",
          "route",
          "course",
          "direction",
          "orientation",
          "alignment",
          "position",
          "location",
          "place",
          "spot",
          "point",
          "site",
          "venue",
          "destination",
          "origin",
          "source",
          "root",
          "base",
          "foundation",
          "core",
          "center",
          "heart",
          "essence",
          "substance",
          "matter",
          "material",
          "stuff",
          "content",
          "subject",
          "topic",
          "theme",
          "focus",
          "emphasis",
          "highlight",
          "feature",
          "aspect",
          "facet",
          "dimension",
          "perspective",
          "viewpoint",
          "angle",
          "side",
          "approach",
          "take",
          "interpretation",
          "understanding",
          "conception",
          "perception",
          "impression",
          "sense",
          "feeling",
          "notion",
          "idea",
          "thought",
          "concept",
          "theory",
          "hypothesis",
          "assumption",
          "premise",
          "proposition",
          "principle",
          "rule",
          "law",
          "regulation",
          "guideline",
          "standard",
          "norm",
          "convention",
          "custom",
          "practice",
          "habit",
          "routine",
          "ritual",
          "tradition",
          "culture",
          "heritage",
          "legacy",
          "history",
          "background",
          "context",
          "environment",
          "setting",
          "circumstance",
          "condition",
          "situation",
          "case",
          "scenario",
          "instance",
          "example",
          "illustration",
          "demonstration",
          "proof",
          "evidence",
          "indication",
          "sign",
          "signal",
          "marker",
          "indicator",
          "symptom",
          "manifestation",
          "expression",
          "representation",
          "symbol",
          "emblem",
          "icon",
          "logo",
          "brand",
          "trademark",
          "signature",
          "mark",
          "imprint",
          "impression",
          "print",
          "stamp",
          "seal",
          "label",
          "tag",
          "badge",
          "sticker",
          "decal",
          "graphic",
          "image",
          "picture",
          "photo",
          "photograph",
          "snapshot",
          "shot",
          "capture",
          "recording",
          "footage",
          "video",
          "film",
          "movie",
          "clip",
          "segment",
          "sequence",
          "series",
          "collection",
          "set",
          "group",
          "batch",
          "lot",
          "bundle",
          "package",
          "parcel",
          "shipment",
          "delivery",
          "consignment",
          "order",
          "purchase",
          "sale",
          "transaction",
          "deal",
          "agreement",
          "contract",
          "arrangement",
          "understanding",
          "commitment",
          "obligation",
          "duty",
          "responsibility",
          "task",
          "assignment",
          "job",
          "work",
          "labor",
          "effort",
          "exertion",
          "struggle",
          "challenge",
          "difficulty",
          "problem",
          "issue",
          "matter",
          "affair",
          "concern",
          "business",
          "subject",
          "topic",
          "theme",
          "motif",
          "idea",
          "concept",
          "notion",
          "thought",
          "impression",
          "perception",
          "view",
          "opinion",
          "belief",
          "conviction",
          "faith",
          "trust",
          "confidence",
          "assurance",
          "certainty",
          "surety",
          "guarantee",
          "warranty",
          "promise",
          "pledge",
          "vow",
          "oath",
          "commitment",
          "dedication",
          "devotion",
          "loyalty",
          "allegiance",
          "fidelity",
          "faithfulness",
          "constancy",
          "steadfastness",
          "firmness",
          "resolution",
          "determination",
          "persistence",
          "perseverance",
          "tenacity",
          "endurance",
          "stamina",
          "strength",
          "power",
          "force",
          "energy",
          "vigor",
          "vitality",
          "life",
          "spirit",
          "soul",
          "heart",
          "mind",
          "intellect",
          "intelligence",
          "reason",
          "logic",
          "sense",
          "judgment",
          "wisdom",
          "knowledge",
          "learning",
          "education",
          "training",
          "instruction",
          "teaching",
          "guidance",
          "direction",
          "leadership",
          "management",
          "administration",
          "governance",
          "government",
          "authority",
          "control",
          "command",
          "power",
          "influence",
          "sway",
          "weight",
          "impact",
          "effect",
          "result",
          "consequence",
          "outcome",
          "end",
          "conclusion",
          "finish",
          "completion",
          "accomplishment",
          "achievement",
          "attainment",
          "success",
          "victory",
          "triumph",
          "win",
        ].join("\n"),
      },
      {
        name: "common-directories.txt",
        content: [
          "admin",
          "login",
          "wp-admin",
          "administrator",
          "phpmyadmin",
          "dashboard",
          "wp-content",
          "upload",
          "uploads",
          "files",
          "images",
          "img",
          "css",
          "js",
          "backup",
          "backups",
          "temp",
          "tmp",
          "private",
          "public",
          "src",
          "api",
          "config",
          "settings",
          "setup",
          "install",
          "docs",
          "documentation",
          "doc",
          "download",
          "downloads",
          "media",
          "static",
          "assets",
          "old",
          "new",
          "test",
          "dev",
          "development",
          "staging",
          "prod",
          "production",
          "beta",
          "alpha",
          "forum",
          "forums",
          "blog",
          "blogs",
          "store",
          "shop",
          "cart",
          "checkout",
          "account",
          "profile",
          "user",
          "users",
          "member",
          "members",
          "admin_area",
          "administrator",
          "webadmin",
          "wp",
          "wordpress",
          "joomla",
          "drupal",
          "cms",
          "system",
          "panel",
          "cp",
          "controlpanel",
          "control",
          "webmail",
          "mail",
          "email",
          "cpanel",
          "ftp",
          "sql",
          "mysql",
          "mssql",
          "oracle",
          "database",
          "db",
          "web",
          "www",
          "w3",
          "intranet",
          "extranet",
          "apps",
          "application",
          "app",
          "api",
          "apis",
          "rest",
          "soap",
          "service",
          "services",
          "site",
          "sites",
          "host",
          "vhost",
          "virtual",
          "secure",
          "ssl",
          "tls",
          "security",
          "auth",
          "authentication",
          "authorize",
          "login",
          "logon",
          "signin",
          "signup",
          "register",
          "password",
          "passwd",
          "user",
          "username",
          "admin",
          "administrator",
          "root",
          "supervisor",
          "su",
          "sudo",
          "admin1",
          "admin2",
          "administrator1",
          "administrator2",
          "superuser",
          "control",
          "panel",
          "cpanel",
          "whm",
          "whmcs",
          "billing",
          "bill",
          "host",
          "hosting",
          "cloud",
          "server",
          "client",
          "portal",
          "support",
          "help",
          "ticket",
          "kb",
          "faq",
          "ask",
          "answer",
          "contact",
          "contactus",
          "about",
          "aboutus",
          "career",
          "careers",
          "job",
          "jobs",
          "work",
          "employment",
          "hire",
          "join",
          "staff",
          "team",
          "partner",
          "partners",
          "reseller",
          "affiliate",
          "affiliates",
          "company",
          "corporate",
          "corporation",
          "org",
          "organization",
          "institute",
          "institution",
          "firm",
          "agency",
          "bureau",
          "office",
          "department",
          "division",
          "unit",
          "branch",
          "subsidiary",
          "group",
          "network",
          "enterprise",
          "business",
          "industry",
          "market",
          "shop",
          "store",
          "mall",
          "marketplace",
          "auction",
          "bid",
          "buy",
          "sell",
          "sale",
          "discount",
          "deal",
          "coupon",
          "promo",
          "promotion",
          "offer",
          "special",
          "price",
          "cost",
          "rate",
          "fee",
          "charge",
          "payment",
          "pay",
          "checkout",
          "cart",
          "basket",
          "bag",
          "order",
          "purchase",
          "transaction",
          "catalog",
          "catalogue",
          "product",
          "products",
          "item",
          "items",
          "goods",
          "merchandise",
          "inventory",
          "stock",
          "supply",
          "supplier",
          "vendor",
          "manufacturer",
          "brand",
          "model",
          "type",
          "category",
          "class",
          "group",
          "collection",
          "series",
          "set",
          "kit",
          "pack",
          "package",
          "bundle",
          "assortment",
          "variety",
          "selection",
          "range",
          "line",
          "list",
          "menu",
          "option",
          "choice",
          "alternative",
          "pick",
          "preference",
          "favorite",
          "wish",
          "wishlist",
          "like",
          "follow",
          "subscribe",
          "membership",
          "plan",
          "program",
          "scheme",
          "system",
          "method",
          "process",
          "procedure",
          "step",
          "stage",
          "phase",
          "level",
          "tier",
          "grade",
          "rank",
          "rating",
          "review",
          "feedback",
          "comment",
          "opinion",
          "view",
          "survey",
          "poll",
          "vote",
          "rating",
          "rank",
          "score",
          "point",
          "credit",
          "bonus",
          "reward",
          "prize",
          "gift",
          "present",
          "award",
          "grant",
          "scholarship",
          "fellowship",
          "fund",
          "funding",
          "finance",
          "financial",
          "money",
          "cash",
          "currency",
          "coin",
          "note",
          "bill",
          "check",
          "cheque",
          "draft",
          "transfer",
          "transaction",
          "deposit",
          "withdrawal",
          "balance",
          "account",
          "banking",
          "bank",
          "credit",
          "debit",
          "loan",
          "mortgage",
          "debt",
          "liability",
          "asset",
          "equity",
          "stock",
          "share",
          "bond",
          "security",
          "investment",
          "investor",
          "portfolio",
          "fund",
          "trust",
          "estate",
          "property",
          "real",
          "realty",
          "land",
          "lot",
          "plot",
          "site",
          "location",
          "place",
          "position",
          "spot",
          "point",
          "area",
          "region",
          "zone",
          "sector",
          "district",
          "quarter",
          "neighborhood",
          "community",
          "society",
          "public",
          "private",
          "personal",
          "individual",
          "group",
          "team",
          "crew",
          "staff",
          "personnel",
          "employee",
          "employer",
          "worker",
          "labor",
          "job",
          "occupation",
          "profession",
          "career",
          "vocation",
          "calling",
          "trade",
          "craft",
          "skill",
          "ability",
          "capability",
          "capacity",
          "competence",
          "expertise",
          "knowledge",
          "know-how",
          "experience",
          "practice",
          "training",
          "education",
          "learning",
          "study",
          "research",
          "development",
          "innovation",
          "invention",
          "discovery",
          "finding",
          "result",
          "outcome",
          "output",
          "product",
          "production",
          "productivity",
          "efficiency",
          "effectiveness",
          "performance",
          "quality",
          "standard",
          "norm",
          "criterion",
          "measure",
          "benchmark",
          "target",
          "goal",
          "objective",
          "aim",
          "purpose",
          "intention",
          "plan",
          "design",
          "scheme",
          "project",
          "program",
          "agenda",
          "schedule",
          "timetable",
          "calendar",
          "date",
          "time",
          "period",
          "duration",
          "interval",
          "term",
          "semester",
          "quarter",
          "month",
          "week",
          "day",
          "hour",
          "minute",
          "second",
          "moment",
          "instant",
          "now",
          "today",
          "tomorrow",
          "yesterday",
          "past",
          "present",
          "future",
          "history",
          "story",
          "account",
          "record",
          "report",
          "document",
          "file",
          "folder",
          "directory",
          "path",
          "location",
          "address",
          "url",
          "uri",
          "link",
          "hyperlink",
          "reference",
          "citation",
          "source",
          "resource",
          "material",
          "content",
          "information",
          "reference",
          "citation",
          "source",
          "resource",
          "material",
          "content",
          "information",
          "data",
          "fact",
          "figure",
          "statistic",
          "number",
          "count",
          "amount",
          "sum",
          "total",
          "whole",
          "part",
          "piece",
          "portion",
          "section",
          "segment",
          "fragment",
          "chunk",
          "bit",
          "element",
          "component",
          "module",
          "unit",
          "item",
          "article",
          "post",
          "entry",
          "record",
          "log",
          "journal",
          "diary",
          "notebook",
          "pad",
          "book",
          "volume",
          "edition",
          "issue",
          "release",
          "version",
          "revision",
          "update",
          "patch",
          "fix",
          "repair",
          "maintenance",
          "service",
          "support",
          "help",
          "desk",
          "center",
          "office",
          "department",
          "division",
          "section",
          "branch",
          "store",
          "shop",
          "market",
          "mall",
          "plaza",
          "center",
          "complex",
          "building",
          "structure",
          "construction",
          "architecture",
          "design",
          "style",
          "fashion",
          "trend",
          "mode",
          "vogue",
          "fad",
          "craze",
          "rage",
          "mania",
          "movement",
          "wave",
          "current",
          "stream",
          "flow",
          "course",
          "direction",
          "way",
          "path",
          "route",
          "road",
          "street",
          "avenue",
          "boulevard",
          "lane",
          "drive",
          "place",
          "circle",
          "square",
          "court",
          "terrace",
          "view",
          "point",
          "outlook",
          "prospect",
          "vista",
          "panorama",
          "scene",
          "scenery",
          "landscape",
          "seascape",
          "cityscape",
          "portrait",
          "picture",
          "image",
          "photo",
          "snapshot",
          "shot",
          "frame",
          "still",
          "capture",
          "print",
          "copy",
          "duplicate",
          "replica",
          "reproduction",
          "imitation",
          "simulation",
          "emulation",
          "virtualization",
          "model",
          "prototype",
          "sample",
          "specimen",
          "example",
          "instance",
          "case",
          "illustration",
          "demonstration",
          "proof",
          "evidence",
          "testimony",
          "witness",
          "account",
          "statement",
          "declaration",
          "affirmation",
          "assertion",
          "claim",
          "allegation",
          "charge",
          "accusation",
          "indictment",
          "complaint",
          "grievance",
          "protest",
          "objection",
          "opposition",
          "resistance",
          "defiance",
          "rebellion",
          "revolt",
          "revolution",
          "uprising",
          "insurrection",
          "mutiny",
          "riot",
          "disturbance",
          "unrest",
          "disorder",
          "chaos",
          "confusion",
          "disarray",
          "disorganization",
          "mess",
          "muddle",
          "jumble",
          "tangle",
          "snarl",
          "knot",
          "complication",
          "difficulty",
          "problem",
          "trouble",
          "issue",
          "matter",
          "affair",
          "concern",
          "business",
          "subject",
          "topic",
          "theme",
          "motif",
          "idea",
          "concept",
          "notion",
          "thought",
          "impression",
          "perception",
          "view",
          "opinion",
          "belief",
          "conviction",
          "faith",
          "trust",
          "confidence",
          "assurance",
          "certainty",
          "surety",
          "guarantee",
          "warranty",
          "promise",
          "pledge",
          "vow",
          "oath",
          "commitment",
          "dedication",
          "devotion",
          "loyalty",
          "allegiance",
          "fidelity",
          "faithfulness",
          "constancy",
          "steadfastness",
          "firmness",
          "resolution",
          "determination",
          "persistence",
          "perseverance",
          "tenacity",
          "endurance",
          "stamina",
          "strength",
          "power",
          "force",
          "energy",
          "vigor",
          "vitality",
          "life",
          "spirit",
          "soul",
          "heart",
          "mind",
          "intellect",
          "intelligence",
          "reason",
          "logic",
          "sense",
          "judgment",
          "wisdom",
          "knowledge",
          "learning",
          "education",
          "training",
          "instruction",
          "teaching",
          "guidance",
          "direction",
          "leadership",
          "management",
          "administration",
          "governance",
          "government",
          "authority",
          "control",
          "command",
          "power",
          "influence",
          "sway",
          "weight",
          "impact",
          "effect",
          "result",
          "consequence",
          "outcome",
          "end",
          "conclusion",
          "finish",
          "completion",
          "accomplishment",
          "achievement",
          "attainment",
          "success",
          "victory",
          "triumph",
          "win",
        ].join("\n"),
      },
    ]

    try {
      // Create each wordlist file
      for (const wordlist of wordlists) {
        const filePath = path.join(directory, wordlist.name)
        fs.writeFileSync(filePath, wordlist.content)
        console.log(`Created wordlist: ${filePath}`)
      }
      return true
    } catch (err) {
      console.error("Error creating default wordlists:", err)
      return false
    }
  }

  // Function to load wordlists
  function loadWordlists() {
    wordlistSelect.innerHTML = '<option value="">Loading wordlists...</option>'

    try {
      // Find wordlists directory
      wordlistsDirectory = findWordlistsDirectory()

      if (!wordlistsDirectory) {
        wordlistSelect.innerHTML = '<option value="">Error: Could not find or create wordlists directory</option>'
        addLog("Error: Could not find or create wordlists directory", "error")
        return
      }

      // Check if directory exists and is readable
      try {
        const stats = fs.statSync(wordlistsDirectory)
        if (!stats.isDirectory()) {
          throw new Error("Not a directory")
        }
      } catch (err) {
        // Try to create directory
        try {
          fs.mkdirSync(wordlistsDirectory, { recursive: true })
          addLog(`Created wordlists directory at ${wordlistsDirectory}`, "info")
        } catch (mkdirErr) {
          wordlistSelect.innerHTML = '<option value="">Error: Could not access wordlists directory</option>'
          addLog(`Error accessing wordlists directory: ${mkdirErr.message}`, "error")
          return
        }
      }

      // Create default wordlists if directory is empty
      try {
        const files = fs.readdirSync(wordlistsDirectory)
        if (files.length === 0) {
          createDefaultWordlists(wordlistsDirectory)
        }
      } catch (err) {
        addLog(`Error reading wordlists directory: ${err.message}`, "error")
      }

      // Read wordlists directory
      try {
        const files = fs.readdirSync(wordlistsDirectory)

        // Filter for .txt files
        const wordlistFiles = files.filter((file) => file.toLowerCase().endsWith(".txt"))

        if (wordlistFiles.length === 0) {
          // No wordlists found, create default ones
          if (createDefaultWordlists(wordlistsDirectory)) {
            // Try reading again
            const newFiles = fs.readdirSync(wordlistsDirectory)
            const newWordlistFiles = newFiles.filter((file) => file.toLowerCase().endsWith(".txt"))

            if (newWordlistFiles.length === 0) {
              wordlistSelect.innerHTML = '<option value="">No wordlists found</option>'
              addLog("No wordlists found even after creating defaults", "error")
              return
            }

            // Populate select with new wordlists
            wordlistSelect.innerHTML = newWordlistFiles
              .map((file) => `<option value="${file}">${file}</option>`)
              .join("")

            addLog(`Created and loaded ${newWordlistFiles.length} default wordlists`, "success")
          } else {
            wordlistSelect.innerHTML = '<option value="">No wordlists found</option>'
            addLog("No wordlists found and failed to create defaults", "error")
          }
        } else {
          // Populate select with found wordlists
          wordlistSelect.innerHTML = wordlistFiles.map((file) => `<option value="${file}">${file}</option>`).join("")

          addLog(`Loaded ${wordlistFiles.length} wordlists from ${wordlistsDirectory}`, "success")
        }
      } catch (err) {
        wordlistSelect.innerHTML = '<option value="">Error loading wordlists</option>'
        addLog(`Error loading wordlists: ${err.message}`, "error")
      }
    } catch (error) {
      console.error("Error in loadWordlists:", error)
      wordlistSelect.innerHTML = '<option value="">Error loading wordlists</option>'
      addLog(`Error loading wordlists: ${error.message}`, "error")
    }
  }

  // Function to start bruteforce
  async function startBruteforce() {
    // Validate inputs
    if (!targetUrlInput.value) {
      showNotification("Please enter a target URL", "error")
      return
    }

    if (!wordlistSelect.value) {
      showNotification("Please select a wordlist", "error")
      return
    }

    try {
      // Reset state
      isRunning = true
      currentIndex = 0
      startTime = Date.now()
      results = []
      statusCounts = {}
      totalRequests = 0
      successfulRequests = 0
      errorRequests = 0
      totalResponseTime = 0
      activeRequests = 0
      abortController = new AbortController()

      // Update UI
      startBtn.disabled = true
      stopBtn.disabled = false
      resultsBody.innerHTML = ""
      if (progressBar) progressBar.style.width = "0%"
      if (progressText) progressText.textContent = "0 / 0 (0%)"
      if (totalRequestsEl) totalRequestsEl.textContent = "0"
      if (elapsedTimeEl) elapsedTimeEl.textContent = "00:00:00"
      if (requestsPerSecondEl) requestsPerSecondEl.textContent = "0"
      if (foundItemsEl) foundItemsEl.textContent = "0"
      if (errorCountEl) errorCountEl.textContent = "0"
      if (avgResponseTimeEl) avgResponseTimeEl.textContent = "0 ms"
      if (statusBarsEl) statusBarsEl.innerHTML = ""

      // Start elapsed time counter
      elapsedTimeInterval = setInterval(updateElapsedTime, 1000)

      // Load wordlist
      const wordlistPath = path.join(wordlistsDirectory, wordlistSelect.value)

      try {
        const wordlistContent = await fs.promises.readFile(wordlistPath, "utf8")
        wordlist = wordlistContent.split("\n").filter((line) => line.trim() !== "")
        addLog(`Loaded wordlist with ${wordlist.length} entries`, "info")
      } catch (error) {
        showNotification(`Error loading wordlist: ${error.message}`, "error")
        stopBruteforce()
        return
      }

      // Update progress
      if (progressText) progressText.textContent = `0 / ${wordlist.length} (0%)`

      // Start bruteforce
      const targetType = targetTypeSelect.value
      const target = targetUrlInput.value
      const threads = Number.parseInt(threadsInput.value)
      const timeout = Number.parseInt(timeoutInput.value)
      const extensions = extensionsInput.value ? extensionsInput.value.split(",").map((ext) => ext.trim()) : []
      const statusCodes = statusCodesInput.value
        ? statusCodesInput.value.split(",").map((code) => Number.parseInt(code.trim()))
        : [200, 204, 301, 302, 307, 401, 403]
      const recursive = recursiveCheckbox.checked
      const followRedirects = followRedirectsCheckbox.checked
      const caseSensitive = caseSensitiveCheckbox.checked

      addLog(`Starting bruteforce on ${target} (${targetType})`, "info")
      addLog(`Threads: ${threads}, Timeout: ${timeout}ms, Extensions: ${extensions.join(", ") || "none"}`, "info")

      // Add progress bar initialization at the beginning of the function
      if (progressContainer) progressContainer.style.display = "block"
      if (progressBar) progressBar.style.width = "0%"
      if (currentWordElement) currentWordElement.textContent = "-"
      if (totalWordsElement) totalWordsElement.textContent = wordlist.length
      if (progressLabel) progressLabel.textContent = 0

      // Process wordlist based on target type
      await processBruteforce(
        target,
        targetType,
        threads,
        timeout,
        extensions,
        statusCodes,
        recursive,
        followRedirects,
        caseSensitive,
      )
    } catch (error) {
      console.error("Error starting bruteforce:", error)
      addLog(`Error starting bruteforce: ${error.message}`, "error")
      stopBruteforce()
    }
  }

  // Function to process bruteforce
  async function processBruteforce(
    target,
    targetType,
    threads,
    timeout,
    extensions,
    statusCodes,
    recursive,
    followRedirects,
    caseSensitive,
  ) {
    // Normalize target
    let baseUrl = target
    if (targetType === "subdomain" && !baseUrl.includes("://")) {
      baseUrl = `http://${baseUrl}`
    }

    // Create URL object to extract parts
    let targetUrl
    try {
      targetUrl = new URL(baseUrl)
    } catch (error) {
      showNotification(`Invalid URL: ${baseUrl}`, "error")
      stopBruteforce()
      return
    }

    // Process wordlist entries in parallel with limited concurrency
    const queue = [...wordlist]
    const activePromises = new Set()

    while (queue.length > 0 && isRunning) {
      // Fill up to max threads
      while (activePromises.size < threads && queue.length > 0 && isRunning) {
        const word = queue.shift()

        // Skip empty words
        if (!word || word.trim() === "") continue

        // Update progress bar
        const progress = Math.floor((currentIndex / wordlist.length) * 100)
        if (progressBar) progressBar.style.width = `${progress}%`
        if (currentWordElement) currentWordElement.textContent = word
        if (progressLabel) progressLabel.textContent = currentIndex

        // Process word based on target type
        const promise = processWord(
          word,
          targetUrl,
          targetType,
          timeout,
          extensions,
          statusCodes,
          followRedirects,
          caseSensitive,
        ).finally(() => {
          activePromises.delete(promise)
        })

        activePromises.add(promise)
        currentIndex++

        // Update progress
        if (showProgressCheckbox && showProgressCheckbox.checked && currentIndex % 10 === 0) {
          const progress = Math.floor((currentIndex / wordlist.length) * 100)
          if (progressBar) progressBar.style.width = `${progress}%`
          if (progressText) progressText.textContent = `${currentIndex} / ${wordlist.length} (${progress}%)`
        }
      }

      // Wait for at least one promise to complete
      if (activePromises.size > 0) {
        await Promise.race(activePromises)
      }
    }

    // Wait for remaining promises
    if (activePromises.size > 0) {
      await Promise.all(activePromises)
    }

    // Bruteforce completed
    if (isRunning) {
      addLog("Bruteforce completed", "success")
      stopBruteforce(true)
      if (progressBar) progressBar.style.width = "100%"
      if (currentWordElement) currentWordElement.textContent = "Complete"
      if (progressLabel) progressLabel.textContent = wordlist.length
    }
  }

  // Function to process a single word
  async function processWord(
    word,
    targetUrl,
    targetType,
    timeout,
    extensions,
    statusCodes,
    followRedirects,
    caseSensitive,
  ) {
    if (!isRunning) return

    // Apply case sensitivity
    if (!caseSensitive) {
      word = word.toLowerCase()
    }

    const urls = []

    // Generate URL based on target type
    switch (targetType) {
      case "subdomain":
        urls.push(new URL(`${targetUrl.protocol}//${word}.${targetUrl.host}`).toString())
        break

      case "directory":
        urls.push(new URL(`${word}/`, targetUrl).toString())
        break

      case "file":
        urls.push(new URL(word, targetUrl).toString())

        // Add extensions if specified
        if (extensions.length > 0) {
          extensions.forEach((ext) => {
            if (!word.endsWith(`.${ext}`)) {
              urls.push(new URL(`${word}.${ext}`, targetUrl).toString())
            }
          })
        }
        break

      case "parameter":
        urls.push(new URL(`?${word}=test`, targetUrl).toString())
        break

      case "vhost":
        // For virtual hosts, we keep the same URL but change the Host header
        urls.push(targetUrl.toString())
        break
    }

    // Process each URL
    for (const url of urls) {
      if (!isRunning) return

      try {
        totalRequests++
        activeRequests++

        // Update stats
        if (totalRequestsEl) totalRequestsEl.textContent = totalRequests.toString()

        const startRequestTime = Date.now()

        // Make request
        const result = await makeRequest(url, timeout, followRedirects, targetType === "vhost" ? word : null)

        const responseTime = Date.now() - startRequestTime
        totalResponseTime += responseTime

        // Special handling for directory brute force and 301/302/307
        let treatAsFound = false;
        let treatAsRedirectToSlash = false;
        if (
          targetType === "directory" &&
          (result.status === 301 || result.status === 302 || result.status === 307) &&
          result.redirectLocation
        ) {
          // Normalize both URLs for comparison
          let testedUrl = new URL(url);
          let redirectUrl;
          try {
            redirectUrl = new URL(result.redirectLocation, testedUrl);
          } catch (e) {
            redirectUrl = null;
          }
          // Check if redirect is to same path with trailing slash
          if (
            redirectUrl &&
            testedUrl.origin === redirectUrl.origin &&
            (
              testedUrl.pathname.replace(/\/$/, "") + "/" === redirectUrl.pathname ||
              testedUrl.pathname + "/" === redirectUrl.pathname
            )
          ) {
            treatAsFound = true;
            treatAsRedirectToSlash = true;
          }
        }

        // Only treat as found if:
        // - status is in user list (statusCodes)
        // - OR it's a directory, 301/302/307, and redirect is to same path with trailing slash
        if (
          statusCodes.includes(result.status) ||
          treatAsFound
        ) {
          // For 301/302/307, if the redirect is NOT to the same path with trailing slash, do not add as found
          if (
            targetType === "directory" &&
            (result.status === 301 || result.status === 302 || result.status === 307) &&
            !treatAsRedirectToSlash &&
            !statusCodes.includes(result.status)
          ) {
            // Do not add to results if not in user statusCodes and not a valid trailing slash redirect
            continue;
          }

          successfulRequests++

          // Add to results
          results.push({
            url: url,
            status: result.status,
            size: result.size,
            time: responseTime,
            contentType: result.contentType,
          })

          // Update status counts
          statusCounts[result.status] = (statusCounts[result.status] || 0) + 1

          // Add to UI
          addResultToTable({
            url: url,
            status: result.status,
            size: result.size,
            time: responseTime,
            contentType: result.contentType,
          })

          // Update stats
          if (foundItemsEl) foundItemsEl.textContent = successfulRequests.toString()

          // Update status bars
          updateStatusBars()

          // Log
          if (treatAsRedirectToSlash) {
            addLog(`Found (redirect to trailing slash): ${url} (${result.status})`, "success")
          } else {
            addLog(`Found: ${url} (${result.status})`, "success")
          }
        }
      } catch (error) {
        errorRequests++
        if (errorCountEl) errorCountEl.textContent = errorRequests.toString()
        addLog(`Error: ${url} - ${error.message}`, "error")
      } finally {
        activeRequests--

        // Update requests per second
        const elapsedSeconds = (Date.now() - startTime) / 1000
        if (elapsedSeconds > 0 && requestsPerSecondEl) {
          requestsPerSecondEl.textContent = Math.round(totalRequests / elapsedSeconds).toString()
        }

        // Update average response time
        if (totalRequests - errorRequests > 0 && avgResponseTimeEl) {
          avgResponseTimeEl.textContent = `${Math.round(totalResponseTime / (totalRequests - errorRequests))} ms`
        }
      }
    }
  }

  // Function to make HTTP request
  async function makeRequest(url, timeout, followRedirects, hostHeader = null) {
    return new Promise((resolve, reject) => {
      try {
        const urlObj = new URL(url)
        const options = {
          method: "GET",
          timeout: timeout,
          headers: {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
          },
        }

        // Add custom host header for vhost enumeration
        if (hostHeader) {
          options.headers["Host"] = hostHeader
        }

        const protocol = urlObj.protocol === "https:" ? https : http

        const req = protocol.request(urlObj, options, (res) => {
          // Handle redirects
          if (
            followRedirects &&
            (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307) &&
            res.headers.location
          ) {
            // Return redirect status and location
            resolve({
              status: res.statusCode,
              size: 0,
              contentType: res.headers["content-type"] || "unknown",
              redirectLocation: res.headers.location
            })
            return
          }

          const chunks = []

          res.on("data", (chunk) => {
            chunks.push(chunk)
          })

          res.on("end", () => {
            const buffer = Buffer.concat(chunks)
            resolve({
              status: res.statusCode,
              size: buffer.length,
              contentType: res.headers["content-type"] || "unknown",
              redirectLocation: null
            })
          })
        })

        req.on("error", (error) => {
          reject(error)
        })

        req.setTimeout(timeout, () => {
          req.destroy()
          reject(new Error("Request timed out"))
        })

        req.end()
      } catch (error) {
        reject(error)
      }
    })
  }

  // Function to add result to table
  function addResultToTable(result) {
    const tr = document.createElement("tr")

    // Format size
    let sizeFormatted
    if (result.size < 1024) {
      sizeFormatted = `${result.size} B`
    } else if (result.size < 1024 * 1024) {
      sizeFormatted = `${(result.size / 1024).toFixed(2)} KB`
    } else {
      sizeFormatted = `${(result.size / (1024 * 1024)).toFixed(2)} MB`
    }

    tr.innerHTML = `
      <td>${result.url}</td>
      <td><span class="status-code code-${result.status}">${result.status}</span></td>
      <td>${sizeFormatted}</td>
      <td>${result.time} ms</td>
      <td>
        <i class="fas fa-copy action-icon copy" title="Copy URL"></i>
        <i class="fas fa-external-link-alt action-icon open" title="Open URL"></i>
      </td>
    `

    // Add event listeners for actions
    tr.querySelector(".copy").addEventListener("click", () => {
      navigator.clipboard
        .writeText(result.url)
        .then(() => showNotification("URL copied to clipboard", "success"))
        .catch((err) => showNotification("Failed to copy URL", "error"))
    })

    tr.querySelector(".open").addEventListener("click", () => {
      // Use IPC to open URL in the main webview
      ipcRenderer.send("open-internal-browser", result.url)
    })

    resultsBody.appendChild(tr)
  }

  // Function to update status bars
  function updateStatusBars() {
    if (!statusBarsEl) return

    statusBarsEl.innerHTML = ""

    // Get total
    const total = Object.values(statusCounts).reduce((sum, count) => sum + count, 0)

    // Sort status codes
    const sortedCodes = Object.keys(statusCounts).sort((a, b) => Number.parseInt(a) - Number.parseInt(b))

    // Create bars
    sortedCodes.forEach((code) => {
      const count = statusCounts[code]
      const percentage = Math.round((count / total) * 100)

      const statusBar = document.createElement("div")
      statusBar.className = "status-bar"
      statusBar.innerHTML = `
        <div class="status-label">${code}</div>
        <div class="status-bar-container">
          <div class="status-bar-fill code-${code}" style="width: ${percentage}%"></div>
        </div>
        <div class="status-count">${count}</div>
      `

      statusBarsEl.appendChild(statusBar)
    })
  }

  // Function to stop bruteforce
  function stopBruteforce(completed = false) {
    if (!isRunning) return

    isRunning = false

    // Cancel ongoing requests
    if (abortController) {
      abortController.abort()
    }

    // Update UI
    startBtn.disabled = false
    stopBtn.disabled = true

    // Stop elapsed time counter
    if (elapsedTimeInterval) {
      clearInterval(elapsedTimeInterval)
    }

    // Log
    if (!completed) {
      addLog("Bruteforce stopped by user", "warning")
    }

    // Auto save results if enabled
    if (autoSaveCheckbox && autoSaveCheckbox.checked && results.length > 0) {
      exportResults()
    }
  }

  // Function to clear results
  function clearResults() {
    results = []
    resultsBody.innerHTML = ""
    if (statusBarsEl) statusBarsEl.innerHTML = ""
    if (logContentEl) logContentEl.innerHTML = ""

    // Reset stats
    totalRequests = 0
    successfulRequests = 0
    errorRequests = 0
    totalResponseTime = 0
    statusCounts = {}

    // Update UI
    if (totalRequestsEl) totalRequestsEl.textContent = "0"
    if (foundItemsEl) foundItemsEl.textContent = "0"
    if (errorCountEl) errorCountEl.textContent = "0"
    if (avgResponseTimeEl) avgResponseTimeEl.textContent = "0 ms"
    if (requestsPerSecondEl) requestsPerSecondEl.textContent = "0"

    addLog("Results cleared", "info")
  }

  // Function to export results
  function exportResults() {
    if (results.length === 0) {
      showNotification("No results to export", "warning")
      return
    }

    try {
      // Create results directory if it doesn't exist
      const resultsDir = path.join(wordlistsDirectory, "..", "results")

      if (!fs.existsSync(resultsDir)) {
        fs.mkdirSync(resultsDir, { recursive: true })
      }

      // Generate filename
      const timestamp = new Date().toISOString().replace(/:/g, "-").replace(/\..+/, "")
      const targetName = targetUrlInput.value.replace(/https?:\/\//, "").replace(/[^a-zA-Z0-9]/g, "_")
      const filename = `${targetName}_${targetTypeSelect.value}_${timestamp}.txt`
      const filepath = path.join(resultsDir, filename)

      // Format results
      let content = `# Bruteforce Results\n`
      content += `# Target: ${targetUrlInput.value}\n`
      content += `# Type: ${targetTypeSelect.value}\n`
      content += `# Date: ${new Date().toISOString()}\n`
      content += `# Total Requests: ${totalRequests}\n`
      content += `# Found Items: ${successfulRequests}\n`
      content += `# Errors: ${errorRequests}\n\n`

      // Add results
      results.forEach((result) => {
        content += `${result.url} [${result.status}] [${result.size} bytes]\n`
      })

      // Write to file
      fs.writeFileSync(filepath, content)

      showNotification(`Results exported to ${filename}`, "success")
      addLog(`Results exported to ${filepath}`, "success")
    } catch (error) {
      console.error("Error exporting results:", error)
      showNotification("Error exporting results", "error")
      addLog(`Error exporting results: ${error.message}`, "error")
    }
  }

  // Function to filter results
  function filterResults() {
    if (!resultsBody) return

    const filterText = filterResultsInput.value.toLowerCase()
    const filterStatus = filterStatusSelect.value

    const rows = resultsBody.querySelectorAll("tr")

    rows.forEach((row) => {
      const url = row.cells[0].textContent.toLowerCase()
      const status = row.cells[1].textContent

      const matchesText = filterText === "" || url.includes(filterText)
      const matchesStatus = filterStatus === "all" || status === filterStatus

      row.style.display = matchesText && matchesStatus ? "" : "none"
    })
  }

  // Function to update elapsed time
  function updateElapsedTime() {
    if (!isRunning || !elapsedTimeEl) return

    const elapsed = Math.floor((Date.now() - startTime) / 1000)
    const hours = Math.floor(elapsed / 3600)
      .toString()
      .padStart(2, "0")
    const minutes = Math.floor((elapsed % 3600) / 60)
      .toString()
      .padStart(2, "0")
    const seconds = Math.floor(elapsed % 60)
      .toString()
      .padStart(2, "0")

    elapsedTimeEl.textContent = `${hours}:${minutes}:${seconds}`
  }

  // Function to add log entry
  function addLog(message, type = "info") {
    if (!logContentEl) return

    const timestamp = new Date().toLocaleTimeString()
    const logEntry = document.createElement("div")
    logEntry.className = `log-entry ${type}`
    logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span> ${message}`

    logContentEl.appendChild(logEntry)
    logContentEl.scrollTop = logContentEl.scrollHeight
  }

  // Function to show notification
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

