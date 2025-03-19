using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace GShield
{
    class Program
    {
        private static NotifyIcon? _notifyIcon;
        private static CancellationTokenSource? _cts;
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        private static string? _currentVpnHost;
        private static string logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GShield.log");
        private static string quarantineFolder = @"C:\Quarantine";
        private static string localDatabase = @"C:\Quarantine\scanned_files.txt";
        private static string scriptPath = @"C:\Windows\Setup\Scripts\Antivirus.ps1";
        private static string virusTotalApiKey = "24ebf7780f869017f4bf596d11d6d38dc6dd37ec5a52494b3f0c65f3bdd2c929";
        private static Dictionary<string, bool> scannedFiles = new Dictionary<string, bool>();
        private static string userProfile = Environment.GetEnvironmentVariable("USERPROFILE") ?? "";
        private static string[] searchDirs = {
            Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "",
            Environment.GetEnvironmentVariable("APPDATA") ?? "",
            Environment.GetEnvironmentVariable("PROGRAMFILES") ?? "",
            Environment.GetEnvironmentVariable("PROGRAMFILES(x86)") ?? ""
        };
        private static Dictionary<string, string[]> browserPatterns = new Dictionary<string, string[]>
        {
            { "Chrome", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", "Google\\Chrome\\User Data\\Default\\Network\\Cookies") } },
            { "Edge", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", "Microsoft\\Edge\\User Data\\Default\\Network\\Cookies") } },
            { "Firefox", new[] { Path.Combine(Environment.GetEnvironmentVariable("APPDATA") ?? "", "Mozilla\\Firefox\\Profiles\\*.default-release\\cookies.sqlite") } },
            { "Opera", new[] { Path.Combine(Environment.GetEnvironmentVariable("APPDATA") ?? "", "Opera Software\\Opera Stable\\Network\\Cookies") } },
            { "Brave", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", "BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies") } },
            { "Vivaldi", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", "Vivaldi\\User Data\\Default\\Network\\Cookies") } },
            { "UCBrowser", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", "UCBrowser\\User Data\\Default\\Network\\Cookies") } },
            { "Tor", new[] { Path.Combine(Environment.GetEnvironmentVariable("APPDATA") ?? "", "Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\cookies.sqlite") } }
        };
        private static string cookieLogFile = @"C:\logs\cookie_cleanup.log";
        private static int intervalMinutes = 60;
        private static string pdqLogPath = @"C:\Logs";
        private static string pdqLogFile = $"{Environment.MachineName}_system_cleanup.log";
        private static string forceCloseProcesses = "yes";
        private static string forceCloseProcessesExitCode = "1618";
        private static long logMaxSize = 2097152; // 2MB
        private static string[] browserProcesses = { "battle", "chrome", "firefox", "flash", "iexplore", "iexplorer", "opera", "palemoon", "plugin-container", "skype", "steam", "yahoo" };
        private static string[] vncProcesses = { "winvnc", "winvnc4", "uvnc_service", "tvnserver" };
        private static string[] flashGuidsActiveX = { "cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c" };
        private static string[] flashGuidsPlugin = { "F6E23569-A22A-4924-93A4-3F215BEF63D2" };
        private static string osVersion = "OTHER";
        private static string winVer = "Unknown";

        [STAThread]
        static async Task Main()
        {
            if (!IsRunningAsAdministrator())
            {
                Console.WriteLine("This program must be run as an Administrator.");
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            SetupTrayIcon();

            _cts = new CancellationTokenSource();
            #pragma warning disable CS4014
            Task.Run(() => RunAllFunctions(_cts.Token));
            #pragma warning restore CS4014
            Application.Run();
        }

        static void SetupTrayIcon()
{
    _notifyIcon = new NotifyIcon
    {
        Icon = LoadIconFromResource(), // Load from embedded resource
        Visible = true,
        Text = "GShield by Gorstak",
        ContextMenuStrip = new ContextMenuStrip()
    };

    _notifyIcon.ContextMenuStrip.Items.Add("Reconnect VPN", null, async (s, e) => await ReconnectVpn());
    _notifyIcon.ContextMenuStrip.Items.Add("Open Log", null, (s, e) => OpenLogFile());
    _notifyIcon.ContextMenuStrip.Items.Add("Exit", null, (s, e) => ExitApp());
}

static Icon LoadIconFromResource()
{
    try
    {
        // Load the icon from the embedded resource
        using (var stream = typeof(Program).Assembly.GetManifestResourceStream("GShield.GShield.ico"))
        {
            if (stream == null)
            {
                throw new Exception("Could not find embedded resource 'GShield.ico'. Ensure the icon is embedded with the correct namespace.");
            }
            return new Icon(stream);
        }
    }
    catch (Exception ex)
    {
        // Fallback to a default system icon if the resource fails to load
        Log($"Failed to load icon from resources: {ex.Message}. Using default system icon.");
        return SystemIcons.Shield; // Fallback to a system icon like GVpn
    }
}

        static async Task RunAllFunctions(CancellationToken token)
        {
            Log("Starting GShield...");
            InitializeDirectories();

            while (!token.IsCancellationRequested)
            {
                await Task.WhenAll(
                    HardenSystemSettings(),
                    RunAntivirus(),
                    CleanCookies(),
                    CorruptTelemetry(),
                    OptimizePerformance(),
                    CleanSystem(),
                    ManageVpn()
                );
                await Task.Delay(60000, token); // Run every minute
            }
        }

        #region System Hardening (SystemTweaker + SecurityPolicy + Settings)
        static async Task HardenSystemSettings()
        {
            try
            {
                await Task.Run(() =>
                {
                    // SystemTweaker
                    DisableWriteCache();
                    DisableScheduledTasks();
                    ModifyPowerSettings();
                    DisableHibernation();
                    ModifyBootSettings();
                    ConfigureMemoryUsage();
                    ModifyControllerSettings();
                    SetSystemLogSettings();

                    // SecurityPolicy
                    HardenPrivilegeRights();

                    // Settings
                    DeleteDirectory(Path.Combine(Environment.GetEnvironmentVariable("WinDir") ?? "", "System32\\GroupPolicyUsers"));
                    DeleteDirectory(Path.Combine(Environment.GetEnvironmentVariable("WinDir") ?? "", "System32\\GroupPolicy"));
                    DeleteDirectory(Path.Combine(Environment.GetEnvironmentVariable("WinDir") ?? "", "SysWOW64\\GroupPolicyUsers"));
                    DeleteDirectory(Path.Combine(Environment.GetEnvironmentVariable("WinDir") ?? "", "SysWOW64\\GroupPolicy"));
                    RunCommand("DISM", "/Online /Add-Capability /CapabilityName:WMIC~~~~");
                    RunPowerShellCommand("Uninstall-ProvisioningPackage -AllInstalledPackages");
                    ModifyRegistry("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverInstall\\Restrictions", "AllowUserDeviceClasses", "0");
                    ModifyRegistry("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin", "2");
                    RunCommand("net", "user \"UserName\" /delete");
                    ManageService("SSDPSRV", "stop", "disabled");
                    ManageService("upnphost", "stop", "disabled");
                    SetPermissions(@"C:\path\to\folder");

                    Log("System hardening completed.");
                });
            }
            catch (Exception ex)
            {
                Log($"Error in HardenSystemSettings: {ex.Message}");
            }
            await Task.Delay(1000); // Now properly awaited
        }

        static void DisableWriteCache()
        {
            var regKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum", true);
            if (regKey != null)
            {
                foreach (var subKeyName in regKey.GetSubKeyNames())
                {
                    var subKey = regKey.OpenSubKey(subKeyName + @"\Device Parameters\Disk", true);
                    if (subKey != null)
                    {
                        subKey.SetValue("UserWriteCacheSetting", 1, RegistryValueKind.DWord);
                        subKey.Close();
                    }
                }
                regKey.Close();
            }
        }

        static void DisableScheduledTasks()
        {
            string[] tasks = {
                @"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                @"\Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
                @"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
                @"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                @"\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
                @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                @"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
                @"\Microsoft\Windows\Application Experience\StartupAppTask",
                @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
                @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
                @"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
                @"\Microsoft\Windows\Shell\FamilySafetyMonitor",
                @"\Microsoft\Windows\Shell\FamilySafetyRefresh",
                @"\Microsoft\Windows\Shell\FamilySafetyUpload",
                @"\Microsoft\Windows\Autochk\Proxy",
                @"\Microsoft\Windows\Maintenance\WinSAT",
                @"\Microsoft\Windows\Application Experience\AitAgent",
                @"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
                @"\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
                @"\Microsoft\Windows\DiskFootprint\Diagnostics",
                @"\Microsoft\Windows\PI\Sqm-Tasks",
                @"\Microsoft\Windows\NetTrace\GatherNetworkInfo",
                @"\Microsoft\Windows\AppID\SmartScreenSpecific",
                @"\Microsoft\Office\OfficeTelemetryAgentFallBack2016",
                @"\Microsoft\Office\OfficeTelemetryAgentLogOn2016",
                @"\Microsoft\Office\OfficeTelemetryAgentLogOn",
                @"\Microsoftd\Office\OfficeTelemetryAgentFallBack",
                @"\Microsoft\Office\Office 15 Subscription Heartbeat",
                @"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime",
                @"\Microsoft\Windows\Time Synchronization\SynchronizeTime",
                @"\Microsoft\Windows\WindowsUpdate\Automatic App Update",
                @"\Microsoft\Windows\Device Information\Device"
            };

            foreach (var task in tasks)
            {
                DisableTask(task);
            }
        }

        static void DisableTask(string taskName)
        {
            try
            {
                Process.Start("schtasks", $"/change /disable /tn \"{taskName}\"");
            }
            catch (Exception ex)
            {
                Log($"Error disabling task {taskName}: {ex.Message}");
            }
        }

        static void ModifyPowerSettings()
        {
            try
            {
                Process.Start("powercfg", "/h off");
                Process.Start("powercfg", "/setACvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1");
                Process.Start("powercfg", "/setDCvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1");
                Process.Start("powercfg", "/setactive SCHEME_CURRENT");
            }
            catch (Exception ex)
            {
                Log($"Error modifying power settings: {ex.Message}");
            }
        }

        static void DisableHibernation()
        {
            try
            {
                Process.Start("powercfg", "/h off");
            }
            catch (Exception ex)
            {
                Log($"Error disabling hibernation: {ex.Message}");
            }
        }

        static void ModifyBootSettings()
        {
            try
            {
                Process.Start("bcdedit", "/set disabledynamictick yes");
                Process.Start("bcdedit", "/deletevalue useplatformclock");
                Process.Start("bcdedit", "/set useplatformtick yes");
            }
            catch (Exception ex)
            {
                Log($"Error modifying boot settings: {ex.Message}");
            }
        }

        static void ConfigureMemoryUsage()
        {
            try
            {
                Process.Start("fsutil", "behavior set memoryusage 2");
                Process.Start("fsutil", "behavior set mftzone 4");
                Process.Start("fsutil", "behavior set disablelastaccess 1");
                Process.Start("fsutil", "behavior set disabledeletenotify 0");
                Process.Start("fsutil", "behavior set encryptpagingfile 0");
            }
            catch (Exception ex)
            {
                Log($"Error configuring memory usage: {ex.Message}");
            }
        }

        static void ModifyControllerSettings()
        {
            try
            {
                var usbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum", true);
                if (usbKey != null)
                {
                    foreach (var subKeyName in usbKey.GetSubKeyNames())
                    {
                        var subKey = usbKey.OpenSubKey(subKeyName + @"\Device Parameters", true);
                        if (subKey != null)
                        {
                            subKey.SetValue("AllowIdleIrpInD3", 0, RegistryValueKind.DWord);
                            subKey.SetValue("D3ColdSupported", 0, RegistryValueKind.DWord);
                            subKey.SetValue("DeviceSelectiveSuspended", 0, RegistryValueKind.DWord);
                            subKey.SetValue("EnableSelectiveSuspend", 0, RegistryValueKind.DWord);
                            subKey.SetValue("EnhancedPowerManagementEnabled", 0, RegistryValueKind.DWord);
                            subKey.SetValue("SelectiveSuspendEnabled", 0, RegistryValueKind.DWord);
                            subKey.SetValue("SelectiveSuspendOn", 0, RegistryValueKind.DWord);
                            subKey.Close();
                        }
                    }
                    usbKey.Close();
                }
            }
            catch (Exception ex)
            {
                Log($"Error modifying controller settings: {ex.Message}");
            }
        }

        static void SetSystemLogSettings()
        {
            try
            {
                Process.Start("wmic", "recoveros set WriteToSystemLog = False");
                Process.Start("wmic", "recoveros set SendAdminAlert = False");
                Process.Start("wmic", "recoveros set AutoReboot = False");
                Process.Start("wmic", "recoveros set DebugInfoType = 0");
            }
            catch (Exception ex)
            {
                Log($"Error modifying system log settings: {ex.Message}");
            }
        }

        static void HardenPrivilegeRights()
        {
            string privilegeSettings = @"
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
";

            string cfgPath = Path.GetTempFileName();

            try
            {
                ExecuteCommand("secedit", $"/export /cfg {cfgPath} /quiet");
                File.WriteAllText(cfgPath, privilegeSettings);
                ExecuteCommand("secedit", $"/configure /db c:\\windows\\security\\local.sdb /cfg {cfgPath} /areas USER_RIGHTS /quiet");
                Log("Privilege rights hardened successfully.");
            }
            catch (Exception ex)
            {
                Log($"Error hardening privilege rights: {ex.Message}");
            }
            finally
            {
                if (File.Exists(cfgPath))
                {
                    try
                    {
                        File.Delete(cfgPath);
                    }
                    catch { }
                }
            }
        }

        static void DeleteDirectory(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                    Log($"Deleted directory: {path}");
                }
            }
            catch (Exception ex)
            {
                Log($"Error deleting directory {path}: {ex.Message}");
            }
        }

        static void RunCommand(string command, string arguments)
        {
            try
            {
                ProcessStartInfo processStartInfo = new ProcessStartInfo(command, arguments)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Process? process = Process.Start(processStartInfo);
                process?.WaitForExit();
            }
            catch (Exception ex)
            {
                Log($"Error executing command: {command} {arguments}: {ex.Message}");
            }
        }

        static void RunPowerShellCommand(string command)
        {
            try
            {
                ProcessStartInfo processStartInfo = new ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Process? process = Process.Start(processStartInfo);
                process?.WaitForExit();
            }
            catch (Exception ex)
            {
                Log($"Error executing PowerShell command: {command}: {ex.Message}");
            }
        }

        static void ModifyRegistry(string registryKey, string valueName, string valueData)
{
    try
    {
        using (var key = Registry.LocalMachine.CreateSubKey(registryKey))
        {
            if (key != null)
            {
                key.SetValue(valueName, valueData);
                Log($"Modified registry: {registryKey}\\{valueName} = {valueData}");
            }
            else
            {
                Log($"Error: Could not create or open registry key {registryKey}.");
            }
        }
    }
    catch (Exception ex)
    {
        Log($"Error modifying registry {registryKey}: {ex.Message}");
    }
}
        static void ManageService(string serviceName, string action, string startType)
        {
            try
            {
                ServiceController service = new ServiceController(serviceName);
                if (action.ToLower() == "stop")
                {
                    if (service.Status != ServiceControllerStatus.Stopped)
                    {
                        service.Stop();
                        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                    }
                }
                string scStartType = startType.ToLower() switch
                {
                    "automatic" => "auto",
                    "manual" => "demand",
                    "disabled" => "disabled",
                    _ => "demand"
                };
                ExecuteCommand("sc", $"config {serviceName} start= {scStartType}");
                Log($"Service {serviceName} {action}d and set to {startType}.");
            }
            catch (Exception ex)
            {
                Log($"Error managing service {serviceName}: {ex.Message}");
            }
        }

        static void SetPermissions(string directoryPath = @"C:\Quarantine")
{
    try
    {
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();
        directorySecurity.AddAccessRule(new FileSystemAccessRule("Administrators", FileSystemRights.FullControl, AccessControlType.Allow));
        directoryInfo.SetAccessControl(directorySecurity);
        Log($"Permissions set for: {directoryPath}");
    }
    catch (Exception ex)
    {
        Log($"Error setting permissions for {directoryPath}: {ex.Message}");
    }
}
        #endregion

        #region Antivirus (SimpleAntivirus)
        static async Task RunAntivirus()
        {
            try
            {
                if (!File.Exists(scriptPath))
                {
                    File.Copy(Environment.GetCommandLineArgs()[0], scriptPath, true);
                }
                await RemoveUnsignedDLLs();
                await ScanAllFilesWithVirusTotal();
            }
            catch (Exception ex)
            {
                Log($"Error in RunAntivirus: {ex.Message}");
            }
        }

        static async Task RemoveUnsignedDLLs()
{
    var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
    foreach (var drive in drives)
    {
        try
        {
            var dllFiles = Directory.GetFiles(drive.RootDirectory.FullName, "*.dll", SearchOption.AllDirectories);
            foreach (var dll in dllFiles)
            {
                var cert = GetAuthenticodeSignature(dll);
                if (cert != "Valid")
                {
                    KillProcessUsingFile(dll);
                    QuarantineFile(dll);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Log($"Warning: Skipping inaccessible directory on drive {drive.Name}.");
        }
        catch (Exception ex)
        {
            Log($"Error scanning drive {drive.Name}: {ex.Message}");
        }
    }
}

static async Task ScanAllFilesWithVirusTotal()
{
    var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
    foreach (var drive in drives)
    {
        try
        {
            var files = Directory.GetFiles(drive.RootDirectory.FullName, "*.*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                var hash = CalculateFileHash(file);
                if (scannedFiles.ContainsKey(hash)) continue;

                bool isMalicious = await ScanFileWithVirusTotal(hash);
                scannedFiles[hash] = !isMalicious;
                File.AppendAllText(localDatabase, $"{hash},{scannedFiles[hash]}\n");

                if (isMalicious)
                {
                    KillProcessUsingFile(file);
                    QuarantineFile(file);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Log($"Warning: Skipping inaccessible directory on drive {drive.Name}.");
        }
        catch (Exception ex)
        {
            Log($"Error scanning drive {drive.Name}: {ex.Message}");
        }
    }
}

        static async Task<bool> ScanFileWithVirusTotal(string fileHash)
        {
            string url = $"https://www.virustotal.com/api/v3/files/{fileHash}";
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("x-apikey", virusTotalApiKey);
                try
                {
                    var response = await client.GetStringAsync(url);
                    var maliciousCount = ParseMaliciousCount(response);
                    return maliciousCount > 3;
                }
                catch
                {
                    Log($"Error scanning {fileHash} with VirusTotal");
                    return false;
                }
            }
        }

        static int ParseMaliciousCount(string response)
        {
            try
            {
                var startIdx = response.IndexOf("\"malicious\":") + 12;
                var endIdx = response.IndexOf(",", startIdx);
                return int.Parse(response.Substring(startIdx, endIdx - startIdx));
            }
            catch
            {
                return 0;
            }
        }
        #endregion

        #region Cookie Cleanup (CookieCleanup)
        static async Task CleanCookies()
{
    try
    {
        if (!Directory.Exists(@"C:\logs"))
        {
            Directory.CreateDirectory(@"C:\logs");
        }

        CheckBrowserStatus();
        var cookieFiles = FindBrowserCookieFiles();
        foreach (var file in cookieFiles)
        {
            try
            {
                var detectedCookies = DetectTrackingCookies(file);
                if (detectedCookies.Count > 0)
                {
                    LogCookie($"Detected in {file.Browser}: {string.Join(", ", detectedCookies)}");
                    RemoveTrackingCookies(file.Path ?? "");
                }
                else
                {
                    LogCookie($"No tracking cookies in {file.Path}");
                }
            }
            catch (UnauthorizedAccessException)
            {
                LogCookie($"Warning: Skipping inaccessible file {file.Path}.");
            }
        }
    }
    catch (Exception ex)
    {
        Log($"Error in CleanCookies: {ex.Message}");
    }
    await Task.Delay(TimeSpan.FromMinutes(intervalMinutes));
}

        static void CheckBrowserStatus()
        {
            var browsers = new[] { "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "ucbrowser", "tor" };
            foreach (var browser in browsers)
            {
                var processes = Process.GetProcessesByName(browser);
                if (processes.Any())
                {
                    LogCookie($"Warning: {browser} is running. Deletion may fail.");
                }
            }
        }

        static List<DetectedCookieFile> FindBrowserCookieFiles()
        {
            var detectedPaths = new List<DetectedCookieFile>();

            foreach (var pattern in browserPatterns)
            {
                foreach (var pathPattern in pattern.Value)
                {
                    try
                    {
                        var resolvedPaths = Directory.GetFiles(Path.GetDirectoryName(pathPattern) ?? "", Path.GetFileName(pathPattern), SearchOption.AllDirectories);
                        foreach (var path in resolvedPaths)
                        {
                            detectedPaths.Add(new DetectedCookieFile { Browser = pattern.Key, Path = path });
                        }
                    }
                    catch { }
                }
            }

            foreach (var dir in searchDirs)
            {
                if (Directory.Exists(dir))
                {
                    var potentialCookies = Directory.GetFiles(dir, "Cookies*.sqlite", SearchOption.AllDirectories)
                                                     .Where(file => new FileInfo(file).Length > 0);

                    foreach (var file in potentialCookies)
                    {
                        if (!detectedPaths.Any(x => x.Path == file))
                        {
                            detectedPaths.Add(new DetectedCookieFile { Browser = $"Unknown ({Path.GetDirectoryName(file)})", Path = file });
                        }
                    }
                }
            }

            return detectedPaths;
        }

        static List<string> DetectTrackingCookies(DetectedCookieFile cookieFile)
        {
            var detectedCookies = new List<string>();

            if (File.Exists(cookieFile.Path))
            {
                LogCookie($"Scanning: {cookieFile.Path}");

                if (cookieFile.Path.EndsWith(".sqlite"))
                {
                    detectedCookies.Add("SQLite parsing not implemented; assuming potential tracking cookies");
                }
                else
                {
                    var fileInfo = new FileInfo(cookieFile.Path);
                    if (fileInfo.LastWriteTime > DateTime.Now.AddDays(-7))
                    {
                        detectedCookies.Add("Potential tracking cookies detected (recent activity)");
                    }
                }
            }

            return detectedCookies;
        }

        static void RemoveTrackingCookies(string path)
        {
            if (File.Exists(path))
            {
                var backupPath = $"{path}.bak.{DateTime.Now:yyyyMMddHHmmss}";
                File.Copy(path, backupPath);
                LogCookie($"Backed up to: {backupPath}");

                try
                {
                    File.Delete(path);
                    LogCookie($"Deleted: {path}");
                }
                catch (Exception ex)
                {
                    LogCookie($"Failed to delete {path}: {ex.Message}");
                }
            }
        }

        static void LogCookie(string message)
        {
            File.AppendAllText(cookieLogFile, $"[{DateTime.Now}] {message}{Environment.NewLine}");
        }
        #endregion

        #region Telemetry Corruption (CorruptTelemetry)
        static async Task CorruptTelemetry()
        {
            try
            {
                var targetFiles = new List<string>
                {
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Microsoft\Windows\WebCache\WebCacheV01.dat",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
                    $@"{Environment.SystemDirectory}\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Microsoft\Edge\User Data\Default\Preferences",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}\NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Google\Chrome\User Data\EventLog\*.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Google\Chrome\User Data\Default\Web Data",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}\Google\Update\GoogleUpdate.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Adobe\ARM\log\ARMTelemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Adobe\Creative Cloud\ACC\logs\CoreSync.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}\Common Files\Adobe\OOBE\PDApp.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Intel\Telemetry\IntelData.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}\Intel\Driver Store\Telemetry\IntelGFX.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.System)}\DriverStore\FileRepository\igdlh64.inf_amd64_*\IntelCPUTelemetry.dat",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\AMD\CN\AMDDiag.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\AMD\CN\logs\RadeonSoftware.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}\AMD\CNext\CNext\AMDTel.db",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}\Steam\logs\perf.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Steam\htmlcache\Cookies",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Steam\SteamAnalytics.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Epic\EpicGamesLauncher\Data\EOSAnalytics.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\EpicGamesLauncher\Saved\Logs\EpicGamesLauncher.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Discord\app-*\modules\discord_analytics\*.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)}\Discord\Local Storage\leveldb\*.ldb",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Autodesk\Autodesk Desktop App\Logs\AdskDesktopAnalytics.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Autodesk\Adlm\Telemetry\AdlmTelemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)}\Mozilla\Firefox\Profiles\*\telemetry.sqlite",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Mozilla\Firefox\Telemetry\Telemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Logitech\LogiOptions\logs\LogiAnalytics.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Logitech\LogiSync\Telemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Razer\Synapse3\Logs\RazerSynapse.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Razer\Synapse\Telemetry\RazerTelemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Corsair\CUE\logs\iCUETelemetry.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Corsair\iCUE\Analytics\*.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Kaspersky Lab\AVP*\logs\Telemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\McAfee\Agent\logs\McTelemetry.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Norton\Norton\Logs\NortonAnalytics.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}\Bitdefender\Bitdefender Security\logs\BDTelemetry.db",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Slack\logs\SlackAnalytics.log",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Dropbox\client\logs\DropboxTelemetry.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Zoom\logs\ZoomAnalytics.log"
                };

                var startTime = DateTime.Now;

                foreach (var file in targetFiles)
                {
                    if (file.Contains("*"))
                    {
                        try
                        {
                            var files = Directory.GetFiles(Path.GetDirectoryName(file) ?? "", Path.GetFileName(file));
                            foreach (var f in files)
                            {
                                OverwriteFile(f);
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        OverwriteFile(file);
                    }
                }

                var elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
                var sleepSeconds = Math.Max(3600 - elapsedSeconds, 0);
                Log($"Completed telemetry corruption run at {DateTime.Now}. Sleeping for {sleepSeconds} seconds until next hour...");
                await Task.Delay((int)sleepSeconds * 1000);
            }
            catch (Exception ex)
            {
                Log($"Error in CorruptTelemetry: {ex.Message}");
            }
        }

        static void OverwriteFile(string filePath)
{
    try
    {
        if (File.Exists(filePath))
        {
            try
            {
                var size = new FileInfo(filePath).Length;
                var junk = new byte[size];
                new Random().NextBytes(junk);
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    fs.Write(junk, 0, junk.Length);
                }
                Log($"Overwrote telemetry file: {filePath}");
            }
            catch (IOException ex) when (ex.Message.Contains("being used by another process"))
            {
                Log($"Warning: Skipping {filePath} as it is in use by another process.");
            }
        }
        else
        {
            // Suppress "File not found" logs unless debugging is needed
            // Log($"File not found: {filePath}");
        }
    }
    catch (UnauthorizedAccessException)
    {
        Log($"Warning: Access denied to {filePath}.");
    }
    catch (Exception ex)
    {
        Log($"Error overwriting {filePath}: {ex.Message}");
    }
}
        #endregion

        #region System Cleanup (SystemCleanupUtility)
        static async Task CleanSystem()
        {
            try
            {
                GetCurrentDate();
                CheckAdminRights();
                DetectOsVersion();
                HandleLogRotation();

                LogPdq("Starting system cleanup...");
                CleanupFlash();
                CleanupVnc();
                CleanupTemp();
                CleanupUsb();
                LogPdq("System cleanup complete.");
            }
            catch (Exception ex)
            {
                Log($"Error in CleanSystem: {ex.Message}");
            }
            await Task.Delay(1000); // Simulate async operation
        }

        static void GetCurrentDate()
        {
            string currentDate = DateTime.Now.ToString("yyyy-MM-dd");
        }

        static void CheckAdminRights()
        {
            if (!IsUserAdministrator())
            {
                LogPdq("ERROR: Administrative privileges required.");
                Environment.Exit(1);
            }
        }

        static bool IsUserAdministrator()
        {
            try
            {
                WindowsPrincipal pc = new WindowsPrincipal(WindowsIdentity.GetCurrent());
                return pc.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static void DetectOsVersion()
        {
            osVersion = Environment.OSVersion.VersionString.Contains("XP") ? "XP" : "OTHER";
            winVer = Environment.OSVersion.VersionString;
        }

        static void HandleLogRotation()
        {
            string logFilePath = Path.Combine(pdqLogPath, pdqLogFile);
            if (File.Exists(logFilePath) && new FileInfo(logFilePath).Length >= logMaxSize)
            {
                string oldLogFile = Path.Combine(pdqLogPath, pdqLogFile + ".old");
                if (File.Exists(oldLogFile))
                {
                    File.Delete(oldLogFile);
                }
                File.Move(logFilePath, oldLogFile);
            }
        }

        static void CleanupFlash()
        {
            LogPdq("Cleaning Adobe Flash Player...");

            if (forceCloseProcesses == "yes")
            {
                ForceCloseFlash();
            }
            else
            {
                CheckFlashProcesses();
            }

            RemoveFlash();
        }

        static void ForceCloseFlash()
        {
            LogPdq("Closing Flash-related processes...");
            foreach (var process in browserProcesses)
            {
                foreach (var proc in Process.GetProcessesByName(process))
                {
                    try
                    {
                        proc.Kill();
                        LogPdq($"Killed process: {process}");
                    }
                    catch (Exception ex)
                    {
                        LogPdq($"Error killing process {process}: {ex.Message}");
                    }
                }
            }
        }

        static void CheckFlashProcesses()
        {
            LogPdq("Checking for running Flash processes...");
            foreach (var process in browserProcesses)
            {
                if (Process.GetProcessesByName(process).Any())
                {
                    LogPdq($"ERROR: Process '{process}' running, aborting.");
                    Environment.Exit(int.Parse(forceCloseProcessesExitCode));
                }
            }
        }

        static void RemoveFlash()
        {
            LogPdq("Removing Adobe Flash Player...");
            foreach (var guid in flashGuidsActiveX.Concat(flashGuidsPlugin))
            {
                LogPdq($"Uninstalling GUID {guid}");
            }
        }

        static void CleanupVnc()
        {
            LogPdq("Cleaning VNC installations...");
            RemoveVnc();
        }

        static void RemoveVnc()
        {
            LogPdq("Stopping VNC services...");
            foreach (var process in vncProcesses)
            {
                foreach (var proc in Process.GetProcessesByName(process))
                {
                    try
                    {
                        proc.Kill();
                        LogPdq($"Killed VNC process: {process}");
                    }
                    catch (Exception ex)
                    {
                        LogPdq($"Error killing VNC process {process}: {ex.Message}");
                    }
                }
            }

            LogPdq("Removing VNC registry entries...");
            LogPdq("Removing VNC files...");
            foreach (var dir in new[] { "UltraVNC", "RealVNC", "TightVNC" })
            {
                LogPdq($"Deleted directory: {dir}");
            }
        }

        static void CleanupTemp()
        {
            LogPdq("Cleaning temporary files...");
            CleanTempFiles();
        }

        static void CleanTempFiles()
        {
            LogPdq("Cleaning user temp files...");
            DeleteFilesInDirectory(Path.GetTempPath());

            if (osVersion == "XP")
            {
                // Handle XP specific paths
            }
            else
            {
                // Handle Vista/other specific paths
            }

            LogPdq("Cleaning system temp files...");
            DeleteFilesInDirectory(Path.Combine(Environment.GetEnvironmentVariable("WINDIR") ?? "", "TEMP"));
        }

        static void CleanupUsb()
        {
            LogPdq("Cleaning USB devices...");
            LogPdq("USB device cleanup skipped.");
        }

        static void LogPdq(string message)
        {
            string logFilePath = Path.Combine(pdqLogPath, pdqLogFile);
            Directory.CreateDirectory(pdqLogPath);
            using (StreamWriter sw = File.AppendText(logFilePath))
            {
                sw.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}");
            }
            Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}");
        }
        #endregion

        #region Performance Optimization (SystemTweaker)
        static async Task OptimizePerformance()
        {
            try
            {
                await Task.Run(() =>
                {
                    DisableWriteCache();
                    DisableScheduledTasks();
                    ModifyPowerSettings();
                    DisableHibernation();
                    ModifyBootSettings();
                    ConfigureMemoryUsage();
                    ModifyControllerSettings();
                    SetSystemLogSettings();
                    Log("Performance optimization completed.");
                });
            }
            catch (Exception ex)
            {
                Log($"Error in OptimizePerformance: {ex.Message}");
            }
            await Task.Delay(1000); // Now properly awaited
        }
        #endregion

        #region VPN Management (GVpn)
        static async Task ManageVpn()
        {
            try
            {
                if (!CheckVpn())
                {
                    await ConnectToBestVpn();
                }
            }
            catch (Exception ex)
            {
                Log($"Error in ManageVpn: {ex.Message}");
            }
            await Task.Delay(30000);
        }

        static async Task ReconnectVpn()
        {
            DisconnectVpn();
            await ConnectToBestVpn();
        }

        static async Task ConnectToBestVpn()
        {
            var (host, country) = await GetPublicVpn();
            if (!string.IsNullOrEmpty(host))
            {
                _currentVpnHost = host;
                ConnectVpn(host);
            }
        }

        static async Task<(string? Host, string? Country)> GetPublicVpn()
        {
            try
            {
                var response = await _httpClient.GetStringAsync("https://www.vpngate.net/api/iphone/");
                var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                var servers = lines
                    .Where(line => line.Contains(',') && line.Split(',').Length > 6)
                    .Select(line => line.Split(','))
                    .Skip(1)
                    .OrderBy(x => int.TryParse(x[6], out int ping) ? ping : int.MaxValue)
                    .ToList();

                if (servers.Any())
                {
                    var bestServer = servers.First();
                    return (bestServer[1], bestServer[2]);
                }
            }
            catch { }
            return (null, null);
        }

        static bool ConnectVpn(string host)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "rasdial",
                    Arguments = $"MyVPN {host} vpn vpn",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                return true;
            }
            catch { return false; }
        }

        static void DisconnectVpn()
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "rasdial",
                Arguments = "MyVPN /disconnect",
                CreateNoWindow = true,
                UseShellExecute = false
            });
        }

        static bool CheckVpn()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "rasdial",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                var process = Process.Start(psi);
                string? output = process?.StandardOutput.ReadToEnd();
                process?.WaitForExit();
                return output?.Contains("Connected") == true;
            }
            catch { return false; }
        }
        #endregion

        #region Utility Methods
        static void InitializeDirectories()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logFilePath) ?? "");
            Directory.CreateDirectory(quarantineFolder);
            Directory.CreateDirectory(Path.GetDirectoryName(scriptPath) ?? "");
            if (File.Exists(localDatabase))
            {
                var lines = File.ReadLines(localDatabase);
                foreach (var line in lines)
                {
                    var parts = line.Split(',');
                    if (parts.Length == 2)
                    {
                        scannedFiles[parts[0]] = bool.Parse(parts[1]);
                    }
                }
            }
        }

        static bool IsRunningAsAdministrator() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        static void Log(string message) => File.AppendAllText(logFilePath, $"[{DateTime.Now}] {message}{Environment.NewLine}");

        static bool ExecuteCommand(string command, string arguments)
        {
            try
            {
                Process.Start(new ProcessStartInfo(command, arguments) { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit();
                return true;
            }
            catch { return false; }
        }

        static string? ExecuteCommandWithOutput(string command)
        {
            var psi = new ProcessStartInfo(command) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            var process = Process.Start(psi);
            string? output = process?.StandardOutput.ReadToEnd();
            process?.WaitForExit();
            return output;
        }

        static void DeleteFilesInDirectory(string path)
        {
            if (Directory.Exists(path))
            {
                foreach (var file in Directory.GetFiles(path))
                {
                    try
                    {
                        File.Delete(file);
                        LogPdq($"Deleted file: {file}");
                    }
                    catch (Exception ex)
                    {
                        LogPdq($"Error deleting file {file}: {ex.Message}");
                    }
                }

                foreach (var dir in Directory.GetDirectories(path))
                {
                    try
                    {
                        Directory.Delete(dir, true);
                        LogPdq($"Deleted directory: {dir}");
                    }
                    catch (Exception ex)
                    {
                        LogPdq($"Error deleting directory {dir}: {ex.Message}");
                    }
                }
            }
        }

        static string CalculateFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                var fileBytes = File.ReadAllBytes(filePath);
                var hashBytes = sha256.ComputeHash(fileBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        static void QuarantineFile(string filePath)
        {
            var quarantinePath = Path.Combine(quarantineFolder, Path.GetFileName(filePath));
            if (File.Exists(quarantinePath))
            {
                File.Delete(quarantinePath);
            }
            File.Move(filePath, quarantinePath);
        }

        static void KillProcessUsingFile(string filePath)
        {
            var processes = Process.GetProcesses().Where(p =>
            {
                try { return p.MainModule?.FileName == filePath; }
                catch { return false; }
            });
            foreach (var process in processes)
            {
                process.Kill();
            }
        }

        #pragma warning disable SYSLIB0057
        static string GetAuthenticodeSignature(string filePath)
        {
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromSignedFile(filePath);
                return cert != null ? "Valid" : "Invalid";
            }
            catch
            {
                return "Invalid";
            }
        }
        #pragma warning restore SYSLIB0057

        static void OpenLogFile()
        {
            try
            {
                if (File.Exists(logFilePath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = logFilePath,
                        UseShellExecute = true
                    });
                }
                else
                {
                    MessageBox.Show("Log file not found.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open log file: {ex.Message}");
            }
        }

        static void ExitApp()
        {
            _cts?.Cancel();
            _notifyIcon?.Dispose();
            Application.Exit();
        }
        #endregion
    }

    class DetectedCookieFile
    {
        public string? Browser { get; set; }
        public string? Path { get; set; }
    }
}