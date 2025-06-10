# tester/launch-mitmweb.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$MitmwebPath
)

Write-Host "Attempting to launch mitmweb..."
Write-Host "Executable Path: $MitmwebPath"

# Define arguments
# --web-host 0.0.0.0 makes it accessible from potentially other devices on the network if needed,
# but 127.0.0.1 restricts it to only your machine. Stick with 127.0.0.1 for default security.
$arguments = "--web-host 127.0.0.1 --web-port 8081 --listen-port 8080 --no-web-open-browser"

Write-Host "Arguments: $arguments"

# Start mitmweb process in a new console window
# Removed -NoNewWindow to make the console visible
# Removed -RedirectStandardOutput as we don't need the file anymore
try {
    $process = Start-Process -FilePath $MitmwebPath -ArgumentList $arguments -PassThru -ErrorAction Stop
    Write-Host "Successfully started mitmweb process with PID: $($process.Id)"
    # The script now simply launches mitmweb and exits.
    # Electron handles the URL and termination.
} catch {
    Write-Error "Failed to start mitmweb process: $_"
    # Exit with a non-zero code to indicate failure
    exit 1
}

# Script finishes here, mitmweb continues running in its own window.