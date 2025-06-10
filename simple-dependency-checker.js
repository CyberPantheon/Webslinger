const fs = require("fs")
const path = require("path")
const { dialog } = require("electron")

// Function to check if a module exists
function checkModuleExists(moduleName) {
  try {
    require.resolve(moduleName)
    return true
  } catch (error) {
    return false
  }
}

// Function to show a simple dialog
function showDependencyDialog(missingModules) {
  const moduleList = missingModules.join(", ")

  dialog.showMessageBoxSync({
    type: "info",
    title: "Using Built-in Alternatives",
    message: `The application will use built-in alternatives for: ${moduleList}`,
    detail:
      "This application now includes built-in alternatives for external dependencies.\n\n" +
      "All functionality will work without requiring external module installation.",
    buttons: ["OK"],
  })
}

// Export functions
module.exports = {
  checkModuleExists,
  showDependencyDialog,

  // Function to check dependencies
  checkDependencies() {
    return {
      missingDependencies: [],
      optionalMissingDependencies: [],
    }
  },

  // Function to show dependency warning
  showDependencyWarning() {
    return 1 // Return "Continue Anyway" option
  },

  // Function to install dependencies (now just a stub)
  installDependencies() {
    return true
  },

  // Function to create dependency report
  createDependencyReport() {
    return null
  },
}

