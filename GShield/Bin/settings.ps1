function Harden-PrivilegeRights {
    # Use here-string with proper formatting
    $privilegeSettings = @'
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeDebugPrivilege=
SeRemoteInteractiveLogonRight=
'@

    # Consider using a more secure temporary path
    $cfgPath = "$env:TEMP\secpol.cfg"
    
    # Add error handling
    try {
        # Export current security policy
        secedit /export /cfg $cfgPath /quiet
        
        # Append new settings
        $privilegeSettings | Out-File -Append -FilePath $cfgPath -ErrorAction Stop
        
        # Apply configuration
        secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet
    }
    catch {
        Write-Error "Error hardening privilege rights: $_"
    }
    finally {
        # Clean up
        if (Test-Path $cfgPath) {
            Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Call the function
Harden-PrivilegeRights
