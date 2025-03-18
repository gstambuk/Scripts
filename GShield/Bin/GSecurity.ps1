# Simple Antivirus by Gorstak

# Define script path
$scriptPath = "C:\Windows\Setup\Scripts\Antivirus.ps1"

# Ensure the script is saved in a known location
if (-not (Test-Path $scriptPath)) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
}

# Define scheduled task parameters
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."

# Check if task exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (-not $existingTask) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription

    # Register the task
    Register-ScheduledTask -TaskName $taskName -InputObject $task
}

# Set up paths
$quarantineFolder = "C:\Quarantine"
$localDatabase = "C:\Quarantine\scanned_files.txt"
$virusTotalApiKey = "24ebf7780f869017f4bf596d11d6d38dc6dd37ec5a52494b3f0c65f3bdd2c929"
$scannedFiles = @{}

# Create Quarantine Folder if it doesn't exist
if (-not (Test-Path -Path $quarantineFolder)) {
    New-Item -Path $quarantineFolder -ItemType Directory
}

# Load previously scanned files into the hash table
if (Test-Path $localDatabase) {
    $lines = Get-Content $localDatabase
    foreach ($line in $lines) {
        $parts = $line -split ','
        if ($parts.Length -eq 2) {
            $scannedFiles[$parts[0]] = [bool]$parts[1]
        }
    }
}

# Remove Unsigned DLLs
function Remove-UnsignedDLLs {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -in @('Fixed', 'Removable', 'Network') }
    foreach ($drive in $drives) {
        $dllFiles = Get-ChildItem -Path $drive.Root -Recurse -Filter *.dll -ErrorAction SilentlyContinue
        foreach ($dll in $dllFiles) {
            $cert = Get-AuthenticodeSignature -FilePath $dll.FullName
            if ($cert.Status -ne 'Valid') {
                Kill-ProcessUsingFile -filePath $dll.FullName
                Quarantine-File -filePath $dll.FullName
            }
        }
    }
}

# Scan all files with VirusTotal
function Scan-AllFilesWithVirusTotal {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -in @('Fixed', 'Removable', 'Network') }
    foreach ($drive in $drives) {
        $files = Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $hash = Calculate-FileHash -filePath $file.FullName
            if ($scannedFiles.ContainsKey($hash)) { continue }
            $isMalicious = Scan-FileWithVirusTotal -fileHash $hash
            $scannedFiles[$hash] = -not $isMalicious
            Add-Content -Path $localDatabase -Value "$hash,$($scannedFiles[$hash])"
            if ($isMalicious) {
                Kill-ProcessUsingFile -filePath $file.FullName
                Quarantine-File -filePath $file.FullName
            }
        }
    }
}

# Scan File with VirusTotal
function Scan-FileWithVirusTotal {
    param (
        [string]$fileHash
    )
    
    $url = "https://www.virustotal.com/api/v3/files/$fileHash"
    $headers = @{ "x-apikey" = $virusTotalApiKey }
    
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        if ($response -and $response.data -and $response.data.attributes) {
            $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
            return $maliciousCount -gt 3
        }
    } catch {
        Write-Host "Error scanning $fileHash with VirusTotal"
    }
    return $false
}

# Calculate File Hash
function Calculate-FileHash {
    param (
        [string]$filePath
    )
    
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    return $hash.Hash.ToLower()
}

# Quarantine File
function Quarantine-File {
    param (
        [string]$filePath
    )
    
    $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
    Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
}

# Kill Processes Using File
function Kill-ProcessUsingFile {
    param (
        [string]$filePath
    )
    
    $processes = Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath -eq $filePath
    }
    
    foreach ($process in $processes) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

# Execute the Scan
while ($true) {
    Remove-UnsignedDLLs
    Scan-AllFilesWithVirusTotal
}
