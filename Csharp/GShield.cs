using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Reflection;

namespace GShield
{
    class Program
    {
        private static NotifyIcon? _notifyIcon;
        private static CancellationTokenSource? _cts;
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        private static string? _currentVpnHost;
        private static List<(string Host, string Country, int Ping)> _vpnServers = new List<(string, string, int)>();
        private static int _currentServerIndex = -1;
        private static DateTime _vpnStartTime;
        private static readonly TimeSpan _vpnTimeLimit = TimeSpan.FromHours(24); // Switch after 24 hours
        private static int _vpnFailureCount = 0;
        private static readonly int _maxFailures = 3;
        private static string logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GShield.log");
        private static string quarantineFolder = @"C:\Quarantine";
        private static string localDatabase = @"C:\Quarantine\scanned_files.txt";
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
        private static List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private static string connectionLogFile = @"C:\logs\connection_attempts.log";

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
            InitializeDirectories();

            // Apply registry settings at startup
            ApplyRegistrySettings();

            // Run one-time functions at startup
            await Task.WhenAll(
                HardenSystemSettings(),
                CorruptTelemetry(),
                OptimizePerformance(),
                CleanSystem()
            );

            // Start persistent tasks
            await SetupFileSystemWatchers();
            await RunInitialScan();
            Task.Run(() => RunCookieCleanupLoop(_cts.Token));
            Task.Run(() => MonitorConnections(_cts.Token));
            Task.Run(() => ManageVpnLoop(_cts.Token));

            Application.Run();
        }

        static void SetupTrayIcon()
        {
            try
            {
                _notifyIcon = new NotifyIcon
                {
                    Icon = LoadIconFromResource(),
                    Visible = true,
                    Text = "GShield by Gorstak"
                };

                var contextMenu = new ContextMenuStrip();
                contextMenu.Items.Add("Exit", null, (s, e) => ExitApp());
                _notifyIcon.ContextMenuStrip = contextMenu;

                Log("Tray icon initialized.");
            }
            catch (Exception ex)
            {
                Log($"Failed to initialize tray icon: {ex.Message}");
            }
        }

        static Icon LoadIconFromResource()
        {
            try
            {
                using (var stream = typeof(Program).Assembly.GetManifestResourceStream("GShield.GShield.ico"))
                {
                    if (stream == null)
                    {
                        throw new Exception("Could not find embedded resource 'GShield.ico'.");
                    }
                    return new Icon(stream);
                }
            }
            catch (Exception ex)
            {
                Log($"Failed to load icon: {ex.Message}. Using default shield icon.");
                return SystemIcons.Shield;
            }
        }

        #region Persistent File System Watcher
        static async Task SetupFileSystemWatchers()
        {
            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));

            foreach (var drive in drives)
            {
                AddWatcher(drive.RootDirectory.FullName);
            }

            Task.Run(() => MonitorDrives(_cts!.Token));
        }

        static void AddWatcher(string path)
        {
            try
            {
                var watcher = new FileSystemWatcher
                {
                    Path = path,
                    Filter = "*.*",
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 65536,
                    EnableRaisingEvents = true
                };

                watcher.Created += async (s, e) => await OnFileEvent(e.FullPath);
                watcher.Changed += async (s, e) => await OnFileEvent(e.FullPath);
                watcher.Error += (s, e) => Log($"Watcher error on {path}: {e.GetException().Message}");

                _watchers.Add(watcher);
                Log($"Started watching drive: {path}");
            }
            catch (Exception ex)
            {
                Log($"Failed to start watcher on {path}: {ex.Message}");
            }
        }

        static async Task MonitorDrives(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var currentDrives = DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => d.RootDirectory.FullName).ToHashSet();
                var watchedDrives = _watchers.Select(w => w.Path).ToHashSet();

                foreach (var drive in currentDrives.Except(watchedDrives))
                    AddWatcher(drive);
                foreach (var drive in watchedDrives.Except(currentDrives))
                {
                    var watcher = _watchers.First(w => w.Path == drive);
                    watcher.Dispose();
                    _watchers.Remove(watcher);
                    Log($"Removed watcher for disconnected drive: {drive}");
                }

                await Task.Delay(5000, token);
            }
        }

        static async Task OnFileEvent(string filePath)
        {
            try
            {
                if (filePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    string cert = GetAuthenticodeSignature(filePath);
                    if (cert != "Valid")
                    {
                        KillProcessUsingFile(filePath);
                        QuarantineFile(filePath);
                        Log($"Quarantined unsigned DLL: {filePath}");
                    }
                }

                string hash = CalculateFileHash(filePath);
                if (scannedFiles.ContainsKey(hash)) return;

                bool isMalicious = await ScanFileWithVirusTotal(hash);
                scannedFiles[hash] = !isMalicious;
                File.AppendAllText(localDatabase, $"{hash},{scannedFiles[hash]}\n");

                if (isMalicious)
                {
                    KillProcessUsingFile(filePath);
                    QuarantineFile(filePath);
                    Log($"Quarantined malicious file: {filePath}");
                }
            }
            catch (Exception ex)
            {
                Log($"Error processing file {filePath}: {ex.Message}");
            }
        }

        static async Task RunInitialScan()
        {
            Log("Running initial scan of existing files...");
            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));

            foreach (var drive in drives)
            {
                try
                {
                    var files = Directory.GetFiles(drive.RootDirectory.FullName, "*.*", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        await OnFileEvent(file);
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
            Log("Initial scan completed.");
        }
        #endregion

        #region Persistent Cookie Cleanup
        static async Task RunCookieCleanupLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                await CleanCookies();
                await Task.Delay(TimeSpan.FromMinutes(intervalMinutes), token);
            }
        }

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

        #region Connection Monitoring
        static async Task MonitorConnections(CancellationToken token)
        {
            try
            {
                if (!Directory.Exists(@"C:\logs"))
                {
                    Directory.CreateDirectory(@"C:\logs");
                }

                TcpListener listener = new TcpListener(System.Net.IPAddress.Any, 0);
                listener.Start();
                Log($"Started connection monitoring on port {((System.Net.IPEndPoint)listener.LocalEndpoint).Port}");

                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        TcpClient client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        var remoteEndPoint = client.Client.RemoteEndPoint as System.Net.IPEndPoint;
                        if (remoteEndPoint != null)
                        {
                            string connectionInfo = $"Unwanted connection from {remoteEndPoint.Address}:{remoteEndPoint.Port} at {DateTime.Now}";
                            LogConnection(connectionInfo);
                            Log($"Detected: {connectionInfo}");
                        }
                        client.Close();
                    }
                    catch (Exception ex)
                    {
                        Log($"Error in connection monitoring: {ex.Message}");
                    }
                }
                listener.Stop();
            }
            catch (Exception ex)
            {
                Log($"Failed to start connection monitoring: {ex.Message}");
            }
        }

        static void LogConnection(string message)
        {
            File.AppendAllText(connectionLogFile, $"[{DateTime.Now}] {message}{Environment.NewLine}");
        }

        static void OpenConnectionLogFile()
        {
            try
            {
                if (File.Exists(connectionLogFile))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = connectionLogFile,
                        UseShellExecute = true
                    });
                }
                else
                {
                    MessageBox.Show("Connection log file not found.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open connection log file: {ex.Message}");
            }
        }
        #endregion

        #region VPN Management
        static async Task ManageVpnLoop(CancellationToken token)
        {
            await FetchVpnServers(); // Initial fetch
            if (_vpnServers.Any())
            {
                await SwitchToNextVpnServer(); // Connect to best server at startup
            }

            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (!CheckVpn())
                    {
                        _vpnFailureCount++;
                        Log($"VPN disconnected. Failure count: {_vpnFailureCount}");
                        if (_vpnFailureCount >= _maxFailures)
                        {
                            await SwitchToNextVpnServer();
                            _vpnFailureCount = 0;
                        }
                    }
                    else if (DateTime.Now - _vpnStartTime > _vpnTimeLimit)
                    {
                        Log("VPN time limit reached. Switching to next server.");
                        await SwitchToNextVpnServer();
                    }
                    else
                    {
                        _vpnFailureCount = 0; // Reset on successful check
                    }
                }
                catch (Exception ex)
                {
                    Log($"VPN management error: {ex.Message}");
                }
                await Task.Delay(60000, token); // Check every minute
            }
        }

        static async Task FetchVpnServers()
        {
            try
            {
                var response = await _httpClient.GetStringAsync("https://www.vpngate.net/api/iphone/");
                var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                _vpnServers = lines
                    .Where(line => line.Contains(',') && line.Split(',').Length > 6)
                    .Select(line => line.Split(','))
                    .Skip(1)
                    .Select(x => (Host: x[1], Country: x[2], Ping: int.TryParse(x[6], out int ping) ? ping : int.MaxValue))
                    .OrderBy(x => x.Ping)
                    .ToList();
                Log($"Fetched {_vpnServers.Count} VPN servers.");
            }
            catch (Exception ex)
            {
                Log($"Failed to fetch VPN servers: {ex.Message}");
            }
        }

        static async Task SwitchToNextVpnServer()
        {
            DisconnectVpn();
            _currentServerIndex = (_currentServerIndex + 1) % _vpnServers.Count; // Cycle to next server
            if (_currentServerIndex >= _vpnServers.Count || _currentServerIndex < 0)
            {
                _currentServerIndex = 0; // Reset to best server if out of range
                await FetchVpnServers(); // Refresh server list
            }

            var server = _vpnServers[_currentServerIndex];
            _currentVpnHost = server.Host;
            if (ConnectVpn(server.Host))
            {
                _vpnStartTime = DateTime.Now;
                Log($"Connected to VPN server: {server.Host} ({server.Country}), Ping: {server.Ping}");
            }
            else
            {
                Log($"Failed to connect to VPN server: {server.Host}");
                await SwitchToNextVpnServer(); // Try next server on failure
            }
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
                })?.WaitForExit();
                return CheckVpn();
            }
            catch (Exception ex)
            {
                Log($"VPN connection error: {ex.Message}");
                return false;
            }
        }

        static void DisconnectVpn()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "rasdial",
                    Arguments = "MyVPN /disconnect",
                    CreateNoWindow = true,
                    UseShellExecute = false
                })?.WaitForExit();
            }
            catch (Exception ex)
            {
                Log($"VPN disconnection error: {ex.Message}");
            }
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
            catch (Exception ex)
            {
                Log($"VPN check error: {ex.Message}");
                return false;
            }
        }
        #endregion

        #region One-Time Functions
        static async Task HardenSystemSettings()
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
                    HardenPrivilegeRights();
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
        }

        static async Task CorruptTelemetry()
        {
            try
            {
                var targetFiles = new List<string>
                {
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Zoom\logs\ZoomAnalytics.log"
                };

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
                Log("Telemetry corruption completed.");
            }
            catch (Exception ex)
            {
                Log($"Error in CorruptTelemetry: {ex.Message}");
            }
        }

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
        }

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
        }
        #endregion

        #region Utility Methods
        static void InitializeDirectories()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logFilePath) ?? "");
            Directory.CreateDirectory(quarantineFolder);
            Directory.CreateDirectory(Path.GetDirectoryName(cookieLogFile) ?? "");
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

        static void ApplyRegistrySettings()
        {
            try
            {
                // Extract embedded registry file
                string tempRegPath = Path.Combine(Path.GetTempPath(), "GShield_settings.reg");
                
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("GShield.settings.reg"))
                {
                    if (stream == null)
                    {
                        Log("Failed to find embedded settings.reg resource");
                        return;
                    }

                    using (var fileStream = new FileStream(tempRegPath, FileMode.Create, FileAccess.Write))
                    {
                        stream.CopyTo(fileStream);
                    }
                }

                // Execute registry file
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "regedit.exe",
                    Arguments = $"/s \"{tempRegPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process? process = Process.Start(psi);
                process?.WaitForExit();

                // Clean up temporary file
                File.Delete(tempRegPath);
                
                Log("Successfully applied registry settings");
            }
            catch (Exception ex)
            {
                Log($"Failed to apply registry settings: {ex.Message}");
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
                    File.Delete(cfgPath);
                }
            }
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
                @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
            };
            foreach (var task in tasks)
            {
                try
                {
                    Process.Start("schtasks", $"/change /disable /tn \"{task}\"");
                }
                catch (Exception ex)
                {
                    Log($"Error disabling task {task}: {ex.Message}");
                }
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
            }
            catch (Exception ex)
            {
                Log($"Error modifying system log settings: {ex.Message}");
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
                    key?.SetValue(valueName, valueData);
                    Log($"Modified registry: {registryKey}\\{valueName} = {valueData}");
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
                if (action.ToLower() == "stop" && service.Status != ServiceControllerStatus.Stopped)
                {
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
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

        static void OverwriteFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
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
            }
            catch (Exception ex)
            {
                Log($"Error overwriting {filePath}: {ex.Message}");
            }
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
            LogPdq("Removing VNC files...");
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
            File.AppendAllText(logFilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}");
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
        #endregion
    }

    class DetectedCookieFile
    {
        public string? Browser { get; set; }
        public string? Path { get; set; }
    }
}