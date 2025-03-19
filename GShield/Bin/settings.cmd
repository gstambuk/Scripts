@echo off

:: Reset group policy
rd /S /Q "%WinDir%\System32\GroupPolicyUsers"
rd /S /Q "%WinDir%\System32\GroupPolicy"
rd /S /Q "%WinDir%\SysWOW64\GroupPolicyUsers"
rd /S /Q "%WinDir%\SysWOW64\GroupPolicy"

:: Wmic
DISM /Online /Add-Capability /CapabilityName:WMIC~~~~

:: Autopilot
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"
rd /s /q %ProgramData%\Microsoft\Provisioning
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions" /v "AllowUserDeviceClasses" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "2" /f

:: Biometrics, Homegroup, and License
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f

:: Riddance
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
    set "USERNAME=%%z"
    set "USERSID=%%y"
)

for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"

for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! (
        echo Removing user: !USERLINE!
        net user "!USERLINE!" /delete
    )
)

:: threats
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /t REG_SZ /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d "1" /f

:: Remove default user
net user defaultuser0 /delete
net user defaultuser1 /delete
net user defaultuser100000 /delete

:: Loop through all network adapters and apply the DisablePXE setting
for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

:: Remove symbolic links
for %%D in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%D:\" (
        for /f "delims=" %%F in ('dir /aL /s /b "%%D:\" 2^>nul') do (
            echo Deleting symbolic link: %%F
            rmdir "%%F" 2>nul || del "%%F" 2>nul
        )
    )
)

:: disable netbios
sc config lmhosts start= disabled
@powershell.exe -ExecutionPolicy Bypass -Command "Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }"
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableNetbios" /t REG_DWORD /d "0" /f

:: takeown of group policy client service
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn setowner -ownr n:Administrators
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn ace -ace "n:Administrators;p:full"
sc stop gpsvc

:: Services stop and disable
sc SSDPSRV start= disabled
sc upnphost start= disabled
sc NetBT start= disabled
sc BTHMODEM start= disabled
sc gpsvc start= disabled
sc LanmanWorkstation start= disabled
sc LanmanServer start= disabled
sc seclogon start= disabled
sc Messenger start= disabled

sc stop SSDPSRV
sc stop upnphost
sc stop NetBT
sc stop BTHMODEM
sc stop gpsvc
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc stop Messenger

:: Perms
for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        takeown /f %%d:\
        icacls %%d:\ /setowner "Administrators"
        icacls %%d:\ /grant:r "Console Logon":M
        icacls %%d:\ /remove "Everyone"
        icacls %%d:\ /remove "Authenticated Users"
        icacls %%d:\ /remove "Users"
    )
)

for %%e in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%e:\ (
        rem Check if the drive is removable
        wmic logicaldisk where "DeviceID='%%e:'" get DriveType 2>nul | find "2" >nul
        if not errorlevel 1 (
            rem Check if the drive is formatted with NTFS
            fsutil fsinfo ntfsinfo %%e:\ >nul 2>&1
            if not errorlevel 1 (
                echo Applying permissions to %%e:\
                takeown /f %%e:\
                icacls %%e:\ /setowner "Administrators"
                icacls %%e:\ /grant:r "Users":RX /T /C
                icacls %%e:\ /grant:r "System":F /T /C
                icacls %%e:\ /grant:r "Administrators":F /T /C
                icacls %%e:\ /grant:r "Authenticated Users":M /T /C
                icacls %%e:\ /grant:r "Console Logon":M
                icacls %%e:\ /remove "Everyone"
                icacls %%e:\ /remove "Authenticated Users"
	        icacls %%e:\ /remove "Users"
            ) else (
                echo %%e:\ is removable but not NTFS formatted.
            )
        ) else (
            echo %%e:\ is not a removable drive.
        )
    )
)

takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:d /T /C
icacls "%SystemDrive%\Users\Public\Desktop" /remove "INTERACTIVE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "SERVICE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "BATCH"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "CREATOR OWNER"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "System"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Administrators"
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d /T /C
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Administrators"

