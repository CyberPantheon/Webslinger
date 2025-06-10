// Assuming this runs in an Electron environment based on original code
const { ipcRenderer, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// DOM Elements
let targetInput, targetTypeSelect, portRangeInput, timingTemplateSelect, interfaceSelect;
let osDetectionCheckbox, versionDetectionCheckbox, scriptScanCheckbox;
let aggressiveScanCheckbox, tracerouteCheckbox, dnsResolutionCheckbox;
let pingScanCheckbox, skipHostDiscoveryCheckbox;
let scanTechniqueRadios, scriptCategoryCheckboxes, scriptIndividualCheckboxes, customScriptsInput;
let additionalOptionsInput, commandPreviewElement; // Changed commandPreviewElement reference below
let startScanBtn, stopScanBtn, clearResultsBtn, exportResultsBtn;
let loadingOverlay, scanProgressBar, scanProgressText;
let rawOutputElement, filterInput, filterStatusSelect;
let hostsBodyEl, portsBodyEl, servicesBodyEl, vulnerabilitiesBodyEl;
let scanInfoEl, hostsSummaryEl, portsSummaryEl, servicesSummaryEl, vulnsSummaryEl, recommendationsEl;

// State variables
let isScanning = false;
let nmapProcess = null;
let scanResults = {
  hosts: [],
  ports: [],
  services: [],
  vulnerabilities: [],
  rawOutput: "",
  summary: {
    totalHosts: 0,
    upHosts: 0,
    downHosts: 0,
    totalPorts: 0,
    openPorts: 0,
    closedPorts: 0,
    filteredPorts: 0,
    totalServices: 0,
    totalVulnerabilities: 0,
  },
};
let scanStartTime = 0;
let scanEndTime = 0;
let nmapPath = ""; // Will be detected
let nmapVersion = "";
let availableScripts = []; // Potentially load if needed for validation/autocomplete
const networkInterfaces = [];

// --- Main Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  initializeElements(); // Get references to all needed DOM elements
  setupEventListeners(); // Add listeners for buttons, inputs, tabs, etc.
  initializeNmap(); // Find Nmap path, version, interfaces
  updateCommandPreview(); // Set initial command preview based on defaults
});

// --- Initialization Functions ---

function initializeElements() {
  // Inputs & Config
  targetInput = document.getElementById("target-input");
  targetTypeSelect = document.getElementById("target-type");
  portRangeInput = document.getElementById("port-range");
  timingTemplateSelect = document.getElementById("timing-template");
  interfaceSelect = document.getElementById("interface");
  osDetectionCheckbox = document.getElementById("os-detection");
  versionDetectionCheckbox = document.getElementById("version-detection");
  scriptScanCheckbox = document.getElementById("script-scan"); // -sC
  aggressiveScanCheckbox = document.getElementById("aggressive-scan"); // -A
  tracerouteCheckbox = document.getElementById("traceroute");
  dnsResolutionCheckbox = document.getElementById("dns-resolution");
  pingScanCheckbox = document.getElementById("ping-scan"); // -sn
  skipHostDiscoveryCheckbox = document.getElementById("skip-host-discovery"); // -Pn
  scanTechniqueRadios = document.querySelectorAll('input[name="scan-technique"]');
  scriptCategoryCheckboxes = document.querySelectorAll(".script-category-cb"); // Use class
  scriptIndividualCheckboxes = document.querySelectorAll(".script-individual-cb"); // Use class
  customScriptsInput = document.getElementById("custom-scripts");
  additionalOptionsInput = document.getElementById("additional-options");
  commandPreviewElement = document.getElementById("command-preview-area"); // *** Use textarea ID ***

  // Action Buttons
  startScanBtn = document.getElementById("start-scan");
  stopScanBtn = document.getElementById("stop-scan");
  clearResultsBtn = document.getElementById("clear-results");
  exportResultsBtn = document.getElementById("export-results");

  // UI Feedback & Output
  loadingOverlay = document.getElementById("loading-overlay");
  scanProgressBar = document.getElementById("scan-progress-bar");
  scanProgressText = document.getElementById("scan-progress-text");
  rawOutputElement = document.getElementById("raw-output");
  filterInput = document.getElementById("filter-results");
  filterStatusSelect = document.getElementById("filter-status");

  // Result Table Bodies
  hostsBodyEl = document.getElementById("hosts-body");
  portsBodyEl = document.getElementById("ports-body");
  servicesBodyEl = document.getElementById("services-body");
  vulnerabilitiesBodyEl = document.getElementById("vulnerabilities-body");

  // Summary Elements
  scanInfoEl = document.getElementById("scan-info");
  hostsSummaryEl = document.getElementById("hosts-summary");
  portsSummaryEl = document.getElementById("ports-summary");
  servicesSummaryEl = document.getElementById("services-summary");
  vulnsSummaryEl = document.getElementById("vulns-summary");
  recommendationsEl = document.getElementById("recommendations");
}

function setupEventListeners() {
    // Window Controls (Electron specific)
    document.getElementById("minimize-btn")?.addEventListener("click", () => ipcRenderer?.send("minimize-window"));
    document.getElementById("close-btn")?.addEventListener("click", () => ipcRenderer?.send("close-window"));

    // Tab Switching
    document.querySelectorAll('.tab-btn').forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab') + '-tab';
            document.querySelector('.tab-btn.active')?.classList.remove('active');
            button.classList.add('active');
            document.querySelector('.tab-pane.active')?.classList.remove('active');
            document.getElementById(targetTab)?.classList.add('active');
        });
    });

    // Collapsible Sections
    document.querySelectorAll('.collapsible-header').forEach(header => {
        header.addEventListener('click', () => {
            const content = header.nextElementSibling;
            const icon = header.querySelector('i'); // Assuming icon is inside header
            const isCurrentlyHidden = content.style.display === 'none' || content.style.display === '';

            content.style.display = isCurrentlyHidden ? 'block' : 'none';
            // Toggle chevron direction (example using font-awesome classes)
            if (icon) {
                icon.classList.toggle('fa-chevron-down', !isCurrentlyHidden);
                icon.classList.toggle('fa-chevron-up', isCurrentlyHidden);
            }
             header.classList.toggle('active', isCurrentlyHidden);
        });
        // Ensure they start collapsed (redundant if CSS handles it, safe otherwise)
        // header.nextElementSibling.style.display = 'none';
        // header.querySelector('i')?.classList.add('fa-chevron-down');
        // header.querySelector('i')?.classList.remove('fa-chevron-up');
    });


  // Scan profile selection
  document.querySelectorAll(".profile-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelector(".profile-btn.active")?.classList.remove("active");
      btn.classList.add("active");
      updateScanProfile(btn.dataset.profile);
    });
  });

  // Copy command button
  document.getElementById("copy-command").addEventListener("click", () => {
    const command = commandPreviewElement.value; // *** Read from textarea value ***
    navigator.clipboard
      .writeText(command)
      .then(() => showNotification("Command copied to clipboard", "success"))
      .catch(() => showNotification("Failed to copy command", "error"));
  });

  // Action buttons
  startScanBtn.addEventListener("click", startScan);
  stopScanBtn.addEventListener("click", stopScan);
  clearResultsBtn.addEventListener("click", clearResults);
  exportResultsBtn.addEventListener("click", exportResults);

  // --- Input change events for command preview ---
  const elementsToWatch = [
    targetInput, targetTypeSelect, portRangeInput, timingTemplateSelect, interfaceSelect,
    osDetectionCheckbox, versionDetectionCheckbox, scriptScanCheckbox, aggressiveScanCheckbox,
    tracerouteCheckbox, dnsResolutionCheckbox, pingScanCheckbox, skipHostDiscoveryCheckbox,
    customScriptsInput, additionalOptionsInput,
    ...scanTechniqueRadios, ...scriptCategoryCheckboxes, ...scriptIndividualCheckboxes
  ];

  elementsToWatch.forEach((element) => {
    if (element) {
      element.addEventListener("input", updateCommandPreview); // For text inputs
      element.addEventListener("change", updateCommandPreview); // For selects, checkboxes, radios
    }
  });

  // Filter results
  filterInput.addEventListener("input", filterResultsTable);
  filterStatusSelect.addEventListener("change", filterResultsTable);
}

async function initializeNmap() {
  try {
    // --- Find Nmap executable (Adapt this logic based on your deployment) ---
    const possiblePaths = [
      (process.resourcesPath ? path.join(process.resourcesPath, 'nmap', 'nmap.exe') : null), // Packaged Electron app
      path.join(process.cwd(), 'nmap', 'nmap.exe'), // Development adjacent folder
      path.join(__dirname, 'nmap', 'nmap.exe'),   // Relative to script
       'nmap' // Assume in system PATH
    ].filter(Boolean); // Remove null paths

    for (const p of possiblePaths) {
        // Basic check for existence (more robust check might be needed)
         if (p === 'nmap' || fs.existsSync(p)) {
              try {
                   // Try getting version to confirm it works
                   const versionTest = spawn(p, ['-V']);
                   let testOutput = '';
                    versionTest.stdout.on('data', data => testOutput += data);
                    await new Promise((resolve, reject) => {
                        versionTest.on('close', code => code === 0 ? resolve() : reject(new Error(`Path ${p} failed version check`)));
                        versionTest.on('error', reject);
                    });
                   nmapPath = p; // Found a working path
                   console.log(`Using Nmap at: ${nmapPath}`);
                   break;
              } catch (err) {
                   console.warn(`Nmap path candidate "${p}" failed test: ${err.message}`);
               }
          }
      }

       if (!nmapPath) {
          throw new Error("Nmap executable not found or not working. Checked paths: " + possiblePaths.join(', '));
       }


    // --- Get Nmap version ---
    const versionProcess = spawn(nmapPath, ["-V"]);
    let versionOutput = "";
    versionProcess.stdout.on("data", (data) => (versionOutput += data.toString()));
    await new Promise((resolve, reject) => {
        versionProcess.on("close", code => code === 0 ? resolve() : reject(new Error('Failed to get Nmap version')));
        versionProcess.on('error', reject);
    });
    const versionMatch = versionOutput.match(/Nmap version ([0-9.]+)/i);
    if (versionMatch) {
      nmapVersion = versionMatch[1];
      console.log(`Nmap version: ${nmapVersion}`);
    }

    // --- Get network interfaces (Using Node's os module) ---
    const interfaces = os.networkInterfaces();
    for (const [name, netInterface] of Object.entries(interfaces)) {
      for (const iface of netInterface) {
        if (iface.family === "IPv4" && !iface.internal) {
          networkInterfaces.push({ name, address: iface.address }); // Store simplified info
          const option = document.createElement("option");
          option.value = name;
          option.textContent = `${name} (${iface.address})`;
          interfaceSelect.appendChild(option);
        }
      }
    }

    // Optional: Get available scripts (can be slow, uncomment if needed)
    /*
    const scriptsProcess = spawn(nmapPath, ['--script', 'help']); // More efficient than 'all'
    let scriptsOutput = '';
    scriptsProcess.stdout.on('data', (data) => scriptsOutput += data.toString());
    await new Promise((resolve) => scriptsProcess.on('close', resolve));
    // Basic parsing, might need refinement
    availableScripts = scriptsOutput.match(/^[a-zA-Z0-9_-]+$/gm) || [];
    console.log(`Found ${availableScripts.length} Nmap scripts (basic check).`);
    */

  } catch (error) {
    console.error("Error initializing Nmap:", error);
    showNotification(`Error initializing Nmap: ${error.message}`, "error");
    // Disable scanning if Nmap isn't found/working
    startScanBtn.disabled = true;
    startScanBtn.title = "Nmap initialization failed";
  }
}

// --- UI Update Functions ---

function updateScanProfile(profile) {
  // Reset common options first
  osDetectionCheckbox.checked = false;
  versionDetectionCheckbox.checked = false;
  scriptScanCheckbox.checked = false; // -sC
  aggressiveScanCheckbox.checked = false; // -A
  tracerouteCheckbox.checked = false;
  pingScanCheckbox.checked = false; // -sn
  skipHostDiscoveryCheckbox.checked = false; // -Pn
  portRangeInput.value = "";
  timingTemplateSelect.value = "3"; // Default T3
  additionalOptionsInput.value = "";
  customScriptsInput.value = "";

  // Uncheck all script categories and individuals
  scriptCategoryCheckboxes.forEach((checkbox) => (checkbox.checked = false));
  scriptIndividualCheckboxes.forEach((checkbox) => (checkbox.checked = false));

  // Set scan technique (defaulting to SYN unless profile overrides)
  const defaultScanTechnique = document.querySelector('input[name="scan-technique"][value="sS"]');
  if (defaultScanTechnique) defaultScanTechnique.checked = true;


  // Apply profile-specific settings
  switch (profile) {
    case "quick":
      // Top ports (Nmap default), SYN scan, T4
      // portRangeInput.value = ""; // Let Nmap use its default top 1k
      timingTemplateSelect.value = "4";
       skipHostDiscoveryCheckbox.checked = true; // Often faster for quick checks
       versionDetectionCheckbox.checked = true; // Get basic service info
      break;
    case "basic":
      // Default ports, SYN, T3, Version Detection
      versionDetectionCheckbox.checked = true;
       skipHostDiscoveryCheckbox.checked = true; // Common for basic scans
      break;
    case "full":
      // All ports, SYN, T4, OS+Version+DefaultScripts+Traceroute
      portRangeInput.value = "1-65535";
      osDetectionCheckbox.checked = true;
      versionDetectionCheckbox.checked = true;
      scriptScanCheckbox.checked = true; // -sC
      tracerouteCheckbox.checked = true;
      timingTemplateSelect.value = "4";
      break;
    case "vuln":
      // Default ports, SYN, T4, Version Detection, Vuln Scripts Category
      versionDetectionCheckbox.checked = true;
      document.getElementById("script-vuln")?.setAttribute("checked", "checked"); // Check the category
       document.querySelector('.script-individual-cb[value="vulners"]')?.setAttribute("checked", "checked"); // Also check vulners script
      timingTemplateSelect.value = "4";
       skipHostDiscoveryCheckbox.checked = true; // Often needed for vuln scans
      break;
    case "custom":
      // Custom scan: Don't change anything, user selects all
      break;
  }

  updateCommandPreview(); // Update the command string based on new settings
}

function updateCommandPreview() {
  if (!nmapPath) { // Don't generate if Nmap isn't ready
      commandPreviewElement.value = "Error: Nmap not initialized.";
      return;
  }

  let command = `nmap`; // Start building the command
  const args = []; // Collect arguments separately for clarity

  // Target (handled at the end)
  const targetValue = targetInput.value || "[target]";
  const targetFlag = targetTypeSelect.value === 'file' ? '-iL' : ''; // Use -iL if file selected

  // Scan technique
  const selectedTechnique = document.querySelector('input[name="scan-technique"]:checked');
  if (selectedTechnique) {
      args.push(`-${selectedTechnique.value}`);
  } else {
      args.push('-sS'); // Default to SYN if none selected (shouldn't happen with radios)
  }


  // Timing template
  args.push(`-T${timingTemplateSelect.value}`);

  // Port range
  if (portRangeInput.value.trim()) {
    args.push(`-p ${portRangeInput.value.trim()}`);
  }

  // Basic Detection Options
  if (aggressiveScanCheckbox.checked) { // -A includes -O, -sV, -sC, --traceroute
      args.push('-A');
       // Disable individual options if -A is checked, as it overrides them
       osDetectionCheckbox.disabled = true;
       versionDetectionCheckbox.disabled = true;
       scriptScanCheckbox.disabled = true;
       tracerouteCheckbox.disabled = true;
  } else {
      // Enable individual options if -A is not checked
       osDetectionCheckbox.disabled = false;
       versionDetectionCheckbox.disabled = false;
       scriptScanCheckbox.disabled = false;
       tracerouteCheckbox.disabled = false;

      if (osDetectionCheckbox.checked) args.push('-O');
      if (versionDetectionCheckbox.checked) args.push('-sV');
      if (scriptScanCheckbox.checked) args.push('-sC'); // Default scripts
      if (tracerouteCheckbox.checked) args.push('--traceroute');
  }


  // Host Discovery Options
  if (pingScanCheckbox.checked) { // -sn disables port scan, overrides most other flags
      args.length = 0; // Clear previous flags if doing only list scan
      args.push('-sn');
       if (!dnsResolutionCheckbox.checked) args.push('-n'); // Can use -n with -sn
      args.push(targetFlag || targetValue); // Add target directly for -sn
       commandPreviewElement.value = `nmap ${args.join(" ")}`;
       return; // Stop building command here for -sn
  } else {
      if (!dnsResolutionCheckbox.checked) args.push('-n'); // Disable DNS resolution
      if (skipHostDiscoveryCheckbox.checked) args.push('-Pn'); // Skip host discovery
  }


  // NSE Scripts
  let scriptArgs = [];
  // Categories
  scriptCategoryCheckboxes.forEach(cb => {
      if (cb.checked) {
          scriptArgs.push(cb.id.replace('script-', ''));
      }
  });
  // Individual Scripts
  scriptIndividualCheckboxes.forEach(cb => {
      if (cb.checked) {
          scriptArgs.push(cb.value);
      }
  });
   // Custom Scripts (append to the list)
   const custom = customScriptsInput.value.trim();
   if (custom) {
       // Split by comma, trim whitespace, filter empty strings
       scriptArgs.push(...custom.split(',').map(s => s.trim()).filter(Boolean));
   }

   // Remove duplicates and add --script argument if any scripts are selected
   if (scriptArgs.length > 0) {
       const uniqueScripts = [...new Set(scriptArgs)]; // Ensure unique script names
       // Avoid adding --script= if -sC or -A is already present and no *other* scripts are selected
       const hasOnlyDefault = uniqueScripts.length === 0 && (scriptScanCheckbox.checked || aggressiveScanCheckbox.checked);
       if (!hasOnlyDefault || uniqueScripts.length > 0) {
            // Filter out 'default' if -sC or -A is checked, as it's redundant
            const finalScriptList = (scriptScanCheckbox.checked || aggressiveScanCheckbox.checked)
                ? uniqueScripts.filter(s => s !== 'default')
                : uniqueScripts;

            if (finalScriptList.length > 0) {
                 // Check if -sC or -A is already pushed
                 const scriptFlagAlreadyPresent = args.includes('-sC') || args.includes('-A');
                 if (scriptFlagAlreadyPresent) {
                      // Append additional scripts to the existing flag if possible (tricky, might be better to just add --script)
                      // Safest approach: just add the --script flag if there are non-default scripts
                       args.push(`--script=${finalScriptList.join(',')}`);
                 } else if (!args.includes('-sC')) { // Only add --script if -sC wasn't pushed AND -A wasn't pushed
                      args.push(`--script=${finalScriptList.join(',')}`);
                 }
            }
       }
   }


  // Network interface
  if (interfaceSelect.value !== "default") {
    args.push(`-e ${interfaceSelect.value}`);
  }

  // Additional options (append raw string)
  if (additionalOptionsInput.value.trim()) {
    args.push(additionalOptionsInput.value.trim());
  }

  // Target (add last, potentially with -iL flag)
  args.push(targetFlag || targetValue);


  // Final command string construction
  command = `nmap ${args.join(" ")}`;

  // Update the textarea value
  commandPreviewElement.value = command;
}

// --- Scan Execution ---

function startScan() {
  if (isScanning) return;
  if (!nmapPath) {
      showNotification("Nmap path not configured or found. Cannot start scan.", "error");
      return;
  }

  // *** Get the command DIRECTLY from the editable preview area ***
  const commandToExecute = commandPreviewElement.value.trim();

  // Basic validation of the command string
  if (!commandToExecute || !commandToExecute.startsWith("nmap")) {
    showNotification("Invalid command in preview area. Must start with 'nmap'.", "error");
    return;
  }

   // Simple check for a target (likely the last argument that doesn't start with '-')
   // This is a basic heuristic and might fail for complex commands.
   const commandPartsHeuristic = commandToExecute.split(" ");
   const potentialTarget = commandPartsHeuristic[commandPartsHeuristic.length - 1];
   if (!potentialTarget || potentialTarget.startsWith('-') && !commandPartsHeuristic.includes('-iL')) {
        showNotification("Warning: No clear target found in the command preview.", "warning");
       // Allow proceeding but warn the user. Consider stricter validation if needed.
   }


  try {
    // Reset UI and state
    resetScanState();
    isScanning = true;
    startScanBtn.disabled = true;
    stopScanBtn.disabled = false;
    loadingOverlay.style.display = "flex";
    scanProgressBar.style.width = "0%";
    scanProgressText.textContent = "Initializing scan...";
    rawOutputElement.textContent = `Executing: ${commandToExecute}\n\n`; // Show the command being run

    scanStartTime = Date.now();

    // *** Parse the command string from the textarea ***
    // This is a simple split; more robust parsing might be needed for quotes, etc.
    const parts = commandToExecute.match(/(?:[^\s"]+|"[^"]*")+/g) || []; // Handle quoted args simply
    const executable = parts[0]; // Should be 'nmap'
    let args = parts.slice(1);

    // *** IMPORTANT: Ensure XML output is requested for parsing ***
    // Check if -oX or -oA is already present
    const hasXmlOutput = args.some(arg => arg === '-oX' || arg === '-oA');
    if (!hasXmlOutput) {
        // Add '-oX -' to output XML to stdout if not specified by user
        args.push('-oX', '-');
        console.log("Added '-oX -' for XML output processing.");
    } else {
        console.log("Command already includes XML output flag (-oX or -oA).");
         // If using -oA, we might need different parsing logic or tell the user XML is preferred.
         // If using -oX file.xml, parsing stdout might fail. Warn user?
         if (args.includes('-oX') && args.indexOf('-oX') + 1 < args.length && args[args.indexOf('-oX') + 1] !== '-') {
              showNotification("Warning: XML output (-oX) is directed to a file. Live results parsing might not work correctly.", "warning");
          }
    }


    console.log("Starting Nmap scan...");
    console.log("Executable:", nmapPath); // Use the detected nmap path
    console.log("Arguments:", args);

    // Spawn Nmap process
    nmapProcess = spawn(nmapPath, args);

    let xmlOutputAccumulator = ""; // Accumulate potential XML output
    let stdoutAccumulator = ""; // Accumulate all stdout
    let stderrAccumulator = ""; // Accumulate stderr

    // --- Process Event Handlers ---
    nmapProcess.stdout.on("data", (data) => {
      const outputChunk = data.toString();
      stdoutAccumulator += outputChunk;
      scanResults.rawOutput += outputChunk; // Append to raw output log
      rawOutputElement.textContent = scanResults.rawOutput; // Update raw view
      rawOutputElement.scrollTop = rawOutputElement.scrollHeight; // Auto-scroll

      // Accumulate if it looks like XML
      if (outputChunk.includes("<?xml") || outputChunk.includes("<nmaprun>") || xmlOutputAccumulator) {
          xmlOutputAccumulator += outputChunk;
       }

      updateScanProgress(outputChunk); // Update progress bar/text
    });

    nmapProcess.stderr.on("data", (data) => {
      const errorChunk = data.toString();
       stderrAccumulator += errorChunk;
      scanResults.rawOutput += `\n--- STDERR ---\n${errorChunk}\n--------------\n`; // Log stderr clearly
      rawOutputElement.textContent = scanResults.rawOutput;
      rawOutputElement.scrollTop = rawOutputElement.scrollHeight;

      // Simple check for common fatal errors
      if (errorChunk.includes("QUITTING!") || errorChunk.includes("Failed to resolve") || errorChunk.includes("requires root privileges")) {
          showNotification(`Nmap Error: ${errorChunk.split('\n')[0]}`, "error"); // Show first line of error
      }
    });

    nmapProcess.on("close", (code) => {
      isScanning = false;
      nmapProcess = null;
      scanEndTime = Date.now();

      startScanBtn.disabled = false;
      stopScanBtn.disabled = true;
      loadingOverlay.style.display = "none";

      console.log(`Nmap process exited with code ${code}`);

      if (code === 0 || (code !== 0 && (xmlOutputAccumulator || stdoutAccumulator)) ) { // Process even if error code if output exists
         if (code !== 0) {
              showNotification(`Scan finished with warnings/errors (code ${code}). Trying to parse results.`, "warning");
          } else {
             showNotification("Scan completed successfully", "success");
          }
          // Prioritize parsing XML output if available
          parseNmapOutput(xmlOutputAccumulator || stdoutAccumulator, !!xmlOutputAccumulator);
      } else {
        showNotification(`Scan failed or produced no output (code ${code})`, "error");
         // Optionally display stderr if no other output
         if (!scanResults.rawOutput && stderrAccumulator) {
              rawOutputElement.textContent = `Scan failed. Error output:\n${stderrAccumulator}`;
          }
      }
       // Ensure filter is reapplied after scan completes if needed
       filterResultsTable();
    });

     nmapProcess.on('error', (err) => {
         console.error("Failed to start Nmap process:", err);
         showNotification(`Failed to start Nmap: ${err.message}`, "error");
         isScanning = false;
         startScanBtn.disabled = false;
         stopScanBtn.disabled = true;
         loadingOverlay.style.display = "none";
     });

  } catch (error) {
    console.error("Error setting up scan:", error);
    showNotification(`Error starting scan: ${error.message}`, "error");
    isScanning = false;
    startScanBtn.disabled = false;
    stopScanBtn.disabled = true;
    loadingOverlay.style.display = "none";
  }
}

function stopScan() {
  if (!isScanning || !nmapProcess) return;

  try {
    // Kill Nmap process (use SIGTERM first, then SIGKILL if needed)
     const killed = nmapProcess.kill('SIGTERM'); // Graceful kill first
     console.log('Attempted to stop Nmap process (SIGTERM)...', killed);

     // Force kill after a short delay if it didn't terminate
      setTimeout(() => {
          if (nmapProcess && !nmapProcess.killed) {
              nmapProcess.kill('SIGKILL');
              console.log('Forced stop Nmap process (SIGKILL)');
          }
      }, 1000); // 1 second grace period


    // State is reset in the 'close' event handler for the process
    showNotification("Scan stop requested", "info");
     // Disable stop button immediately
     stopScanBtn.disabled = true;


  } catch (error) {
    console.error("Error stopping scan:", error);
    showNotification(`Error stopping scan: ${error.message}`, "error");
     // Force UI reset just in case
     isScanning = false;
     nmapProcess = null;
     startScanBtn.disabled = false;
     stopScanBtn.disabled = true;
     loadingOverlay.style.display = "none";
  }
}

function resetScanState() {
    // Clear previous results object
    scanResults = {
        hosts: [], ports: [], services: [], vulnerabilities: [], rawOutput: "",
        summary: { totalHosts: 0, upHosts: 0, downHosts: 0, totalPorts: 0, openPorts: 0, closedPorts: 0, filteredPorts: 0, totalServices: 0, totalVulnerabilities: 0 }
    };

    // Clear UI Tables and Summaries
    hostsBodyEl.innerHTML = '<tr><td colspan="6" class="placeholder">Scan results will appear here.</td></tr>';
    portsBodyEl.innerHTML = '<tr><td colspan="6" class="placeholder">Scan results will appear here.</td></tr>';
    servicesBodyEl.innerHTML = '<tr><td colspan="6" class="placeholder">Scan results will appear here.</td></tr>';
    vulnerabilitiesBodyEl.innerHTML = '<tr><td colspan="6" class="placeholder">Scan results will appear here.</td></tr>';

    scanInfoEl.innerHTML = '<p class="placeholder">Scan summary will appear here.</p>';
    hostsSummaryEl.innerHTML = '<p class="placeholder">Hosts summary will appear here.</p>';
    portsSummaryEl.innerHTML = '<p class="placeholder">Ports summary will appear here.</p>';
    servicesSummaryEl.innerHTML = '<p class="placeholder">Services summary will appear here.</p>';
    vulnsSummaryEl.innerHTML = '<p class="placeholder">Vulnerabilities summary will appear here.</p>';
    recommendationsEl.innerHTML = '<div class="card-header"><i class="fas fa-lightbulb"></i><h3>Recommendations</h3></div><div class="card-content"><p class="placeholder">Recommendations will appear after scanning.</p></div>';
    rawOutputElement.textContent = ""; // Clear raw output view too
}


function clearResults() {
  resetScanState(); // Use the reset function
  showNotification("Results cleared", "info");
}

// --- Result Processing & Display ---

function updateScanProgress(outputChunk) {
  // Try to extract Nmap progress percentage (works with -v or specific scripts)
  // Example: "Scanning 1 host [1 port/host]"
  // Example: "Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan"
  // Example: Timing: About 45.67% done; ETC: 15:30 (0:00:12 remaining)
    const progressMatch = outputChunk.match(/Timing: About ([0-9.]+)% done/);
    if (progressMatch && progressMatch[1]) {
        const progress = parseFloat(progressMatch[1]);
        scanProgressBar.style.width = `${progress}%`;
        scanProgressText.textContent = `Scan Progress: ${progress.toFixed(1)}%`;
        loadingOverlay.querySelector('.loading-status').textContent = outputChunk.split('\n').find(line => line.includes('Timing:')) || 'Scanning...';
    } else {
        // Fallback: Update status text with the latest line containing "Scanning" or "Stats"
        const statusLine = outputChunk.split('\n').reverse().find(line => line.includes('Scanning') || line.includes('Stats:'));
        if (statusLine) {
             loadingOverlay.querySelector('.loading-status').textContent = statusLine.trim();
        }
    }
}


function parseNmapOutput(outputData, isLikelyXml) {
  console.log("Parsing Nmap output...");
  resetScanState(); // Clear previous results before parsing new ones
  scanResults.rawOutput = outputData; // Store the full raw output used for parsing
  rawOutputElement.textContent = outputData; // Display raw output immediately

  try {
    // Simple check for XML structure
    if (isLikelyXml && outputData.includes("<nmaprun") && outputData.includes("</nmaprun>")) {
      console.log("Attempting to parse as XML...");
      parseNmapXML(outputData);
    } else {
      console.log("Attempting to parse as Standard Output...");
      parseNmapStdout(outputData); // Fallback to parsing stdout format
    }

    updateResultsUI(); // Populate tables and summaries
    generateRecommendations(); // Generate actionable advice

  } catch (error) {
    console.error("Error parsing Nmap output:", error);
    showNotification(`Error parsing scan results: ${error.message}`, "error");
    // Display raw output even if parsing fails
    rawOutputElement.textContent = `Error parsing results. Raw output:\n\n${outputData}`;
  }
}


function parseNmapXML(xmlString) {
    // Use DOMParser for safer and more robust XML parsing
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlString, "text/xml");

     // Check for parser errors
     const parseError = xmlDoc.querySelector("parsererror");
     if (parseError) {
         console.error("XML Parse Error:", parseError.textContent);
         throw new Error("Failed to parse Nmap XML output.");
     }

    const hosts = xmlDoc.querySelectorAll("host");
    scanResults.summary.totalHosts = hosts.length;

    hosts.forEach(hostNode => {
        const hostData = {
            address: hostNode.querySelector('address[addrtype="ipv4"]')?.getAttribute('addr') || '',
            hostname: hostNode.querySelector('hostnames hostname')?.getAttribute('name') || '',
            status: hostNode.querySelector('status')?.getAttribute('state') || 'unknown',
            os: 'Unknown',
            openPorts: 0,
            ports: [] // Store detailed port info here temporarily
        };

        if (hostData.status === 'up') scanResults.summary.upHosts++;
        else scanResults.summary.downHosts++;

        // OS Detection
        const osMatch = hostNode.querySelector('os osmatch');
        if (osMatch) {
            hostData.os = `${osMatch.getAttribute('name')} (${osMatch.getAttribute('accuracy')}%)`;
        } else {
             const osClass = hostNode.querySelector('os osclass'); // Fallback
             if (osClass) hostData.os = osClass.getAttribute('osfamily') || 'Detected';
        }


        // Ports
        const portNodes = hostNode.querySelectorAll('ports port');
        scanResults.summary.totalPorts += portNodes.length;

        portNodes.forEach(portNode => {
            const portId = portNode.getAttribute('portid');
            const protocol = portNode.getAttribute('protocol');
            const stateNode = portNode.querySelector('state');
            const serviceNode = portNode.querySelector('service');
            const scripts = portNode.querySelectorAll('script');

            const portData = {
                host: hostData.address || hostData.hostname,
                port: portId,
                protocol: protocol,
                state: stateNode?.getAttribute('state') || 'unknown',
                service: serviceNode?.getAttribute('name') || '',
                version: [
                    serviceNode?.getAttribute('product'),
                    serviceNode?.getAttribute('version'),
                    serviceNode?.getAttribute('extrainfo')
                ].filter(Boolean).join(' ') || ''
            };

            scanResults.ports.push(portData); // Add to global port list

            // Update Summaries
            if (portData.state === 'open') {
                 scanResults.summary.openPorts++;
                 hostData.openPorts++;
                 hostData.ports.push(portId); // Add to host's open port list
            } else if (portData.state === 'closed') {
                 scanResults.summary.closedPorts++;
            } else if (portData.state === 'filtered') {
                 scanResults.summary.filteredPorts++;
             }


            // Add to Services Summary (if open)
            if (portData.state === 'open' && portData.service) {
                const serviceName = portData.service;
                let serviceEntry = scanResults.services.find(s => s.name === serviceName && s.version === portData.version);
                if (!serviceEntry) {
                    serviceEntry = { name: serviceName, version: portData.version, ports: [], hosts: [] };
                    scanResults.services.push(serviceEntry);
                }
                const portString = `${portId}/${protocol}`;
                if (!serviceEntry.ports.includes(portString)) serviceEntry.ports.push(portString);
                if (!serviceEntry.hosts.includes(portData.host)) serviceEntry.hosts.push(portData.host);
            }


            // Process Scripts for Vulnerabilities
            scripts.forEach(scriptNode => {
                 const scriptId = scriptNode.getAttribute('id');
                 const scriptOutput = scriptNode.getAttribute('output');

                 // Simple check for vuln indicators (adjust as needed)
                 if (scriptId && scriptOutput && (scriptId.includes('vuln') || scriptId.includes('exploit') || scriptOutput.toLowerCase().includes('vulnerable') || scriptOutput.includes('CVE-'))) {
                     let severity = "info"; // Default severity
                      // Basic severity keywords (improve with CVE lookup if possible)
                      if (scriptOutput.match(/Severity: CRITICAL/i)) severity = "critical";
                      else if (scriptOutput.match(/Severity: HIGH/i)) severity = "high";
                      else if (scriptOutput.match(/Severity: MEDIUM/i)) severity = "medium";
                      else if (scriptOutput.match(/Severity: LOW/i)) severity = "low";
                      else if (scriptId.includes('vuln') || scriptId.includes('exploit')) severity = "medium"; // Default for vuln scripts


                     scanResults.vulnerabilities.push({
                         host: portData.host,
                         port: portId,
                         service: portData.service,
                         name: scriptId,
                         severity: severity,
                         details: scriptOutput.trim() // Trim whitespace
                     });
                 }
             });

        });

        scanResults.hosts.push(hostData); // Add processed host data
    });

     scanResults.summary.totalServices = scanResults.services.length;
     scanResults.summary.totalVulnerabilities = scanResults.vulnerabilities.length;

     console.log("XML Parsing complete. Summary:", scanResults.summary);
}


function parseNmapStdout(stdoutData) {
  // --- Fallback parser for standard Nmap output ---
  // This is less reliable than XML but provides basic info.
  const lines = stdoutData.split('\n');
  let currentHost = null;

  lines.forEach(line => {
    line = line.trim();
    if (!line) return;

    // Host lines: "Nmap scan report for hostname (ip.address)" or "Nmap scan report for ip.address"
    const hostMatch = line.match(/^Nmap scan report for (?:([^\s(]+)\s+\(([^)]+)\)|([^)\s]+))/);
    if (hostMatch) {
      const hostname = hostMatch[1] || '';
      const address = hostMatch[2] || hostMatch[3]; // IP is either in parens or the only thing
       currentHost = scanResults.hosts.find(h => h.address === address); // Check if host already added (e.g., from initial ping)
       if (!currentHost) {
            currentHost = { address, hostname, status: 'up', os: 'Unknown', openPorts: 0, ports: [] };
            scanResults.hosts.push(currentHost);
            scanResults.summary.totalHosts++; // Assume total = up for stdout parsing
            scanResults.summary.upHosts++;
       } else {
            currentHost.status = 'up'; // Mark as up if port scan info follows
            if (hostname && !currentHost.hostname) currentHost.hostname = hostname; // Update hostname if found
       }
      return; // Move to next line
    }

    // Host down line
    if (line.match(/Host seems down/i) && currentHost) {
         currentHost.status = 'down';
         scanResults.summary.upHosts--; // Adjust count
         scanResults.summary.downHosts++;
         currentHost = null; // Stop processing ports for this host
         return;
    }


    // Port lines: "PORT STATE SERVICE VERSION" e.g., "80/tcp open http Apache httpd 2.4.18"
    const portMatch = line.match(/^(\d+)\/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?/);
    if (portMatch && currentHost && currentHost.status === 'up') {
      const port = portMatch[1];
      const protocol = portMatch[2];
      const state = portMatch[3];
      const service = portMatch[4];
      const version = portMatch[5] ? portMatch[5].trim() : '';

       const portData = { host: currentHost.address, port, protocol, state, service, version };
       scanResults.ports.push(portData);
       scanResults.summary.totalPorts++;


      if (state === 'open') {
          scanResults.summary.openPorts++;
          currentHost.openPorts++;
          currentHost.ports.push(port);

          // Add to services summary
           if (service) {
               let serviceEntry = scanResults.services.find(s => s.name === service && s.version === version);
               if (!serviceEntry) {
                   serviceEntry = { name: service, version: version, ports: [], hosts: [] };
                   scanResults.services.push(serviceEntry);
               }
               const portString = `${port}/${protocol}`;
               if (!serviceEntry.ports.includes(portString)) serviceEntry.ports.push(portString);
               if (!serviceEntry.hosts.includes(currentHost.address)) serviceEntry.hosts.push(currentHost.address);
           }
      } else if (state === 'closed') {
           scanResults.summary.closedPorts++;
      } else if (state === 'filtered') {
           scanResults.summary.filteredPorts++;
       }
    }

    // Basic OS Detection line
     const osMatch = line.match(/OS details: (.*)/i);
     if (osMatch && currentHost && currentHost.status === 'up') {
         currentHost.os = osMatch[1].trim();
     }

     // Basic Script Output / Vulnerability (Very rudimentary)
     // Look for lines starting with '|' or '_' often indicating script output
      if (line.startsWith('|') || line.startsWith('|_')) {
           const scriptOutput = line.substring(line.indexOf(' ')).trim(); // Get content after ID
           if (scriptOutput && currentHost && currentHost.ports.length > 0) { // Associate with last open port of current host
                const lastOpenPort = scanResults.ports.slice().reverse().find(p => p.host === currentHost.address && p.state === 'open');
                if (lastOpenPort && (scriptOutput.toLowerCase().includes('vulnerable') || scriptOutput.includes('CVE-')) ) {
                    scanResults.vulnerabilities.push({
                        host: currentHost.address,
                        port: lastOpenPort.port,
                        service: lastOpenPort.service,
                        name: 'Script Output (Parsed from Stdout)',
                        severity: 'medium', // Default for stdout parsing
                        details: scriptOutput
                    });
                    scanResults.summary.totalVulnerabilities++;
                }
           }
      }

  });
   scanResults.summary.totalServices = scanResults.services.length;
   console.log("Stdout Parsing complete. Summary:", scanResults.summary);

}


function updateResultsUI() {
  const { summary, hosts, ports, services, vulnerabilities } = scanResults;
  const scanDuration = (scanEndTime > scanStartTime) ? ((scanEndTime - scanStartTime) / 1000).toFixed(2) : "N/A";

  // --- Scan Summary Tab ---
  scanInfoEl.innerHTML = `
    <div class="scan-info-item"><strong>Target:</strong> ${targetInput.value || 'N/A'}</div>
    <div class="scan-info-item"><strong>Duration:</strong> ${scanDuration} seconds</div>
    <div class="scan-info-item"><strong>Nmap Version:</strong> ${nmapVersion || 'Unknown'}</div>
    <div class="scan-info-item command-used"><strong>Command Used:</strong> <pre>${commandPreviewElement.value || 'N/A'}</pre></div>
  `;

  hostsSummaryEl.innerHTML = `
    <div class="summary-stat"><div class="stat-value">${summary.totalHosts}</div><div class="stat-label">Scanned</div></div>
    <div class="summary-stat"><div class="stat-value up">${summary.upHosts}</div><div class="stat-label">Up</div></div>
    <div class="summary-stat"><div class="stat-value down">${summary.downHosts}</div><div class="stat-label">Down</div></div>
  `;

  portsSummaryEl.innerHTML = `
    <div class="summary-stat"><div class="stat-value">${summary.totalPorts}</div><div class="stat-label">Scanned</div></div>
    <div class="summary-stat"><div class="stat-value open">${summary.openPorts}</div><div class="stat-label">Open</div></div>
    <div class="summary-stat"><div class="stat-value closed">${summary.closedPorts}</div><div class="stat-label">Closed</div></div>
    <div class="summary-stat"><div class="stat-value filtered">${summary.filteredPorts}</div><div class="stat-label">Filtered</div></div>
  `;

  servicesSummaryEl.innerHTML = `
    <div class="summary-stat"><div class="stat-value">${summary.totalServices}</div><div class="stat-label">Unique Services</div></div>
    ${services.length > 0 ? `
      <div class="top-services">
        <h4>Top Services (${Math.min(5, services.length)}):</h4>
        <ul>${services.slice(0, 5).map(s => `<li>${s.name} (${s.hosts.length} hosts)</li>`).join('')}</ul>
      </div>` : '<p class="placeholder">No services detected.</p>'}
  `;

  vulnsSummaryEl.innerHTML = `
    <div class="summary-stat"><div class="stat-value">${summary.totalVulnerabilities}</div><div class="stat-label">Potential Vulns</div></div>
    ${vulnerabilities.length > 0 ? `
      <div class="vuln-breakdown">
        <div class="vuln-severity critical">${vulnerabilities.filter(v => v.severity === 'critical').length} C</div>
        <div class="vuln-severity high">${vulnerabilities.filter(v => v.severity === 'high').length} H</div>
        <div class="vuln-severity medium">${vulnerabilities.filter(v => v.severity === 'medium').length} M</div>
        <div class="vuln-severity low">${vulnerabilities.filter(v => v.severity === 'low').length} L</div>
        <div class="vuln-severity info">${vulnerabilities.filter(v => v.severity === 'info').length} I</div>
      </div>` : '<p class="placeholder">No vulnerabilities detected.</p>'}
  `;

  // --- Hosts Tab ---
  hostsBodyEl.innerHTML = hosts.length > 0
    ? hosts.map(host => `
      <tr data-status="${host.status}" data-hostname="${host.hostname}" data-address="${host.address}">
        <td>${host.hostname || host.address}${host.hostname && host.address !== host.hostname ? ` (${host.address})` : ''}</td>
        <td><span class="status-badge status-${host.status}">${host.status}</span></td>
        <td>${host.os}</td>
        <td>${host.openPorts}</td>
        <td>${host.latency || 'N/A'}</td>
        <td>
          <button class="action-icon" title="Copy IP" onclick="navigator.clipboard.writeText('${host.address}')"><i class="fas fa-copy"></i></button>
          </td>
      </tr>`).join('')
    : '<tr><td colspan="6" class="placeholder">No host results.</td></tr>';

  // --- Ports Tab ---
  portsBodyEl.innerHTML = ports.length > 0
    ? ports.map(port => `
      <tr data-status="${port.state}" data-host="${port.host}" data-port="${port.port}" data-service="${port.service}">
        <td>${port.host}</td>
        <td>${port.port}</td>
        <td>${port.protocol}</td>
        <td><span class="status-badge status-${port.state}">${port.state}</span></td>
        <td>${port.service}</td>
        <td>${port.version}</td>
      </tr>`).join('')
    : '<tr><td colspan="6" class="placeholder">No port results.</td></tr>';

    // --- Services Tab ---
    servicesBodyEl.innerHTML = services.length > 0
     ? services.sort((a,b) => a.name.localeCompare(b.name)).map(service => `
        <tr data-service="${service.name}">
            <td>${service.name}</td>
            <td>${service.ports.length > 5 ? service.ports.slice(0,5).join(', ') + '...' : service.ports.join(', ')} (${service.ports.length})</td>
            <td>${service.ports[0]?.split('/')[1] || 'N/A'}</td>
            <td>${service.version}</td>
            <td>${service.hosts.length > 5 ? service.hosts.slice(0,5).join(', ') + '...' : service.hosts.join(', ')} (${service.hosts.length})</td>
            <td></td>
        </tr>
     `).join('')
     : '<tr><td colspan="6" class="placeholder">No unique services identified.</td></tr>';


  // --- Vulnerabilities Tab ---
  vulnerabilitiesBodyEl.innerHTML = vulnerabilities.length > 0
    ? vulnerabilities.sort((a,b) => { // Sort by severity
         const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
         return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      }).map(vuln => `
      <tr data-status="${vuln.severity}" data-host="${vuln.host}" data-port="${vuln.port}" data-service="${vuln.service}">
        <td>${vuln.host}</td>
        <td>${vuln.port}</td>
        <td>${vuln.service}</td>
        <td>${vuln.name}</td>
        <td><span class="status-badge severity-${vuln.severity}">${vuln.severity}</span></td>
        <td class="vuln-details">
           <button class="action-icon" title="Show Details" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'block' ? 'none' : 'block'"><i class="fas fa-info-circle"></i></button>
           <pre class="details-popup">${vuln.details}</pre>
         </td>
      </tr>`).join('')
    : '<tr><td colspan="6" class="placeholder">No vulnerabilities detected.</td></tr>';

    // Apply filtering after updating UI
    filterResultsTable();
}


function generateRecommendations() {
    const { summary, ports, services, vulnerabilities } = scanResults;
    const recommendations = [];

    // Vulnerability based
    if (summary.totalVulnerabilities > 0) {
        const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
        const high = vulnerabilities.filter(v => v.severity === 'high').length;
        recommendations.push(`Address the ${summary.totalVulnerabilities} potential vulnerabilities found, prioritizing the ${critical} critical and ${high} high severity findings.`);
    }

    // Open Ports & Firewalling
    if (summary.openPorts > 0) {
        recommendations.push(`Review the ${summary.openPorts} open ports detected. Ensure each is necessary and consider implementing or tightening firewall rules to restrict access to only authorized sources.`);
         const worldReadablePorts = ports.filter(p => p.state === 'open' && !['localhost', '127.0.0.1'].includes(p.host)); // Simple check
         if (worldReadablePorts.length > 0) {
              recommendations.push(`Specifically examine ports like ${worldReadablePorts.slice(0,3).map(p => p.port + '/' + p.protocol).join(', ')} which appear open externally.`);
          }
    }

    // Insecure Services
    if (services.some(s => s.name === 'telnet')) recommendations.push('Telnet service detected. Replace with SSH for secure remote administration.');
    if (services.some(s => s.name === 'ftp' && !s.name.includes('sftp') && !s.name.includes('ftps'))) recommendations.push('FTP service detected. Use SFTP or FTPS for secure file transfers.');
    if (services.some(s => s.name === 'http' && !s.name.includes('https')) && !services.some(s => s.name === 'https')) recommendations.push('HTTP service found without HTTPS. Implement TLS/SSL encryption for web traffic.');

    // Outdated Service Versions (Basic Check)
     const oldIndicators = ['old', 'outdated', 'end-of-life', 'eol', 'deprecated'];
     const outdatedServices = services.filter(s => s.version && oldIndicators.some(ind => s.version.toLowerCase().includes(ind)));
     if (outdatedServices.length > 0) {
         recommendations.push(`Update or patch potentially outdated services: ${outdatedServices.map(s => `${s.name} (${s.version})`).slice(0,2).join(', ')}...`);
     }


    // General Best Practices
    if (summary.upHosts > 0) {
        recommendations.push('Perform regular vulnerability scans and patch management.');
        if (!vulnerabilities.some(v => v.name.includes('smb-vuln-ms17-010')) && services.some(s=>s.name.includes('microsoft-ds') || s.name.includes('netbios-ssn')) ) {
             // If SMB is open but MS17-010 wasn't found (maybe scan didn't check?), still recommend patching.
            recommendations.push('Ensure systems are patched against critical vulnerabilities like MS17-010 (EternalBlue) if SMB is exposed.');
        }
    }


    // Update UI
    if (recommendations.length > 0) {
        recommendationsEl.innerHTML = `
            <div class="card-header"><i class="fas fa-lightbulb"></i><h3>Recommendations</h3></div>
            <div class="card-content">
                <ul class="recommendations-list">
                    ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>`;
    } else if (summary.totalHosts > 0) {
         recommendationsEl.innerHTML = `
             <div class="card-header"><i class="fas fa-lightbulb"></i><h3>Recommendations</h3></div>
             <div class="card-content"><p>No specific high-priority recommendations based on this scan. Review open ports and services for necessity.</p></div>`;
     } else {
        // Keep placeholder if no scan run
         recommendationsEl.innerHTML = `
             <div class="card-header"><i class="fas fa-lightbulb"></i><h3>Recommendations</h3></div>
             <div class="card-content"><p class="placeholder">Recommendations will appear after scanning.</p></div>`;
     }
}

function filterResultsTable() {
    const filterText = filterInput.value.toLowerCase();
    const filterStatus = filterStatusSelect.value; // e.g., "all", "open", "up", "critical"

    // Iterate through each result table's body rows
    document.querySelectorAll('.results-table tbody').forEach(tbody => {
        tbody.querySelectorAll('tr').forEach(row => {
             // Skip placeholder rows
             if (row.querySelector('.placeholder')) {
                  row.style.display = ''; // Show placeholder if table is empty after filter
                  return;
              }

            const rowText = row.textContent.toLowerCase();
            const status = row.dataset.status || ''; // Get status from data attribute

            const matchesText = filterText === '' || rowText.includes(filterText);
            const matchesStatus = filterStatus === 'all' || status === filterStatus;

            row.style.display = matchesText && matchesStatus ? '' : 'none';
        });

         // Show placeholder if all rows in a table are hidden by filter
         const visibleRows = Array.from(tbody.querySelectorAll('tr')).filter(r => r.style.display !== 'none' && !r.querySelector('.placeholder'));
         const placeholderRow = tbody.querySelector('tr .placeholder');
         if (placeholderRow) {
              placeholderRow.parentElement.style.display = visibleRows.length === 0 ? '' : 'none';
              if (visibleRows.length === 0) {
                  placeholderRow.textContent = `No results match filter "${filterText}" / status "${filterStatus}".`;
              }
          }
    });
}

// --- Utility Functions ---

function showNotification(message, type = "info") {
  // Create notification element dynamically
  const notificationEl = document.createElement("div");
  notificationEl.className = `notification ${type}`; // Apply type class (info, success, warning, error)
  notificationEl.textContent = message;

  document.body.appendChild(notificationEl);

  // Trigger animation/display
  setTimeout(() => {
    notificationEl.style.opacity = "1";
    notificationEl.style.transform = "translateY(0)";
  }, 10); // Small delay to allow CSS transition

  // Auto-hide after a few seconds
  setTimeout(() => {
    notificationEl.style.opacity = "0";
    notificationEl.style.transform = "translateY(-20px)";
    setTimeout(() => {
      notificationEl.remove(); // Remove from DOM after fade out
    }, 500); // Match transition duration
  }, 3500); // Notification visible duration
}

function exportResults() {
  if (!scanResults || scanResults.hosts.length === 0) {
    showNotification("No scan results to export.", "warning");
    return;
  }

  try {
    // Create results directory if it doesn't exist (using Node.js fs)
    const resultsDir = path.join(os.homedir(), 'nmap-scanner-results'); // Save to user's home dir
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    // Generate filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    // Sanitize target input for filename
    const targetSanitized = (targetInput.value || 'scan').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
    const baseFilename = `nmap_${targetSanitized}_${timestamp}`;

    // --- Export Formats ---

    // 1. Raw Output (.txt)
    const rawPath = path.join(resultsDir, `${baseFilename}_raw.txt`);
    fs.writeFileSync(rawPath, scanResults.rawOutput || "No raw output captured.");

    // 2. Parsed Results (.json)
    const jsonPath = path.join(resultsDir, `${baseFilename}_parsed.json`);
    // Create a storable version of results (exclude raw output from JSON)
     const resultsToStore = { ...scanResults, rawOutput: undefined };
    fs.writeFileSync(jsonPath, JSON.stringify(resultsToStore, null, 2)); // Pretty print JSON

    // 3. Basic CSV (Hosts and Open Ports) - Example
     const csvPath = path.join(resultsDir, `${baseFilename}_summary.csv`);
     let csvContent = "Host Address,Hostname,Status,OS,Open Port,Protocol,Service,Version\n";
     scanResults.ports.filter(p => p.state === 'open').forEach(p => {
         const hostInfo = scanResults.hosts.find(h => h.address === p.host) || {};
         csvContent += `"${p.host}","${hostInfo.hostname || ''}","${hostInfo.status || 'up'}","${hostInfo.os || ''}","${p.port}","${p.protocol}","${p.service}","${p.version}"\n`;
     });
     fs.writeFileSync(csvPath, csvContent);


    showNotification(`Results exported to ${resultsDir}`, "success");

     // Open the directory (Electron specific)
     shell?.openPath(resultsDir).catch(err => console.error("Failed to open results directory:", err));


  } catch (error) {
    console.error("Error exporting results:", error);
    showNotification(`Error exporting results: ${error.message}`, "error");
  }
}