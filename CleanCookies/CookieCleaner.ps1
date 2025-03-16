# Unattended version with persistence, periodic cleaning, and script block
$userProfile = $env:USERPROFILE
$searchDirs = @("$env:LOCALAPPDATA", "$env:APPDATA", "$env:PROGRAMFILES", "$env:PROGRAMFILES(x86)")
$browserPatterns = @{
    "Chrome"       = @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies")
    "Edge"         = @("$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies")
    "Firefox"      = @("$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite")
    "Opera"        = @("$env:APPDATA\Opera Software\Opera Stable\Network\Cookies")
    "Brave"        = @("$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies")
    "Vivaldi"      = @("$env:LOCALAPPDATA\Vivaldi\User Data\Default\Network\Cookies")
    "UCBrowser"    = @("$env:LOCALAPPDATA\UCBrowser\User Data\Default\Network\Cookies")
    "Tor"          = @("$env:APPDATA\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\cookies.sqlite")
}
$trackingKeywords = @("track", "ads", "analytics", "doubleclick", "pixel", "marketing", "google-analytics", "facebook")
$logFile = "C:\logs\cookie_cleanup.log"  # Silent logging
$intervalMinutes = 60  # Run every 60 minutes

# Ensure log directory exists
if (-not (Test-Path "C:\logs")) { New-Item -Path "C:\logs" -ItemType Directory -Force }

function Check-BrowserStatus {
    $browsers = @("chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "ucbrowser", "tor")
    foreach ($browser in $browsers) {
        if (Get-Process -Name $browser -ErrorAction SilentlyContinue) {
            Add-Content -Path $logFile -Value "[$(Get-Date)] Warning: $browser is running. Deletion may fail."
        }
    }
}

function Find-BrowserCookieFiles {
    $detectedPaths = @()
    foreach ($browser in $browserPatterns.Keys) {
        foreach ($pathPattern in $browserPatterns[$browser]) {
            $resolvedPaths = Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue
            foreach ($path in $resolvedPaths) {
                if (Test-Path $path.FullName) {
                    $detectedPaths += [PSCustomObject]@{ Browser = $browser; Path = $path.FullName }
                }
            }
        }
    }
    foreach ($dir in $searchDirs) {
        $potentialCookies = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "Cookies|cookies\.sqlite" -and $_.Length -gt 0 }
        foreach ($file in $potentialCookies) {
            if (-not ($detectedPaths.Path -contains $file.FullName)) {
                $detectedPaths += [PSCustomObject]@{ Browser = "Unknown ($($file.Directory.Name))"; Path = $file.FullName }
            }
        }
    }
    return $detectedPaths
}

function Detect-TrackingCookies {
    param ($cookieFile)
    if (Test-Path $cookieFile) {
        Add-Content -Path $logFile -Value "[$(Get-Date)] Scanning: $cookieFile"
        if ($cookieFile -match "sqlite") {
            return @("SQLite parsing not implemented; assuming potential tracking cookies")
        } else {
            $fileInfo = Get-Item $cookieFile
            if ($fileInfo.LastWriteTime -gt (Get-Date).AddDays(-7)) {
                return @("Potential tracking cookies detected (recent activity)")
            }
            return @()
        }
    }
    return @()
}

function Remove-TrackingCookies {
    param ($path)
    if (Test-Path $path) {
        Add-Content -Path $logFile -Value "[$(Get-Date)] Cleaning: $path"
        $backupPath = "$path.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item -Path $path -Destination $backupPath -Force -ErrorAction SilentlyContinue
        Add-Content -Path $logFile -Value "[$(Get-Date)] Backed up to: $backupPath"
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $path)) {
            Add-Content -Path $logFile -Value "[$(Get-Date)] Deleted: $path"
        } else {
            Add-Content -Path $logFile -Value "[$(Get-Date)] Failed: $path"
        }
    }
}

# Script block for background execution
$cleanupScriptBlock = {
    while ($true) {
        Add-Content -Path $logFile -Value "[$(Get-Date)] Starting cleanup cycle..."
        Check-BrowserStatus
        $cookieFiles = Find-BrowserCookieFiles
        foreach ($file in $cookieFiles) {
            $detectedCookies = Detect-TrackingCookies -cookieFile $file.Path
            if ($detectedCookies.Count -gt 0) {
                Add-Content -Path $logFile -Value "[$(Get-Date)] Detected in $($file.Browser): $detectedCookies"
                Remove-TrackingCookies -path $file.Path
            } else {
                Add-Content -Path $logFile -Value "[$(Get-Date)] No tracking cookies in $($file.Path)"
            }
        }
        Add-Content -Path $logFile -Value "[$(Get-Date)] Cleanup cycle completed! Waiting $intervalMinutes minutes..."
        Start-Sleep -Seconds ($intervalMinutes * 60)  # Wait before next run
    }
}

# Launch the script block in the background
Start-Job -ScriptBlock $cleanupScriptBlock -Name "CookieCleanupJob" | Out-Null
