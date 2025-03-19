function Harden-PrivilegeRights {
    # Ensure script is run as Administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as an Administrator."
        return
    }

    # Privilege rights settings
    $privilegeSettings = @'
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
'@

    # Secure temp file path
    $cfgPath = [System.IO.Path]::GetTempFileName()

    try {
        # Export current security policy
        secedit /export /cfg $cfgPath /quiet

        # Write new settings
        Set-Content -Path $cfgPath -Value $privilegeSettings -ErrorAction Stop

        # Apply new security policy
        secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet

        Write-Output "Privilege rights hardened successfully."
    }
    catch {
        Write-Error "Error hardening privilege rights: $_"
    }
    finally {
        # Clean up temp file
        if (Test-Path $cfgPath) {
            Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Execute function
Harden-PrivilegeRights

