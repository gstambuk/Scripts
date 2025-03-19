using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CookieCleanup
{
    class Program
    {
        static string userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
        static string[] searchDirs = { 
            Environment.GetEnvironmentVariable("LOCALAPPDATA"),
            Environment.GetEnvironmentVariable("APPDATA"),
            Environment.GetEnvironmentVariable("PROGRAMFILES"),
            Environment.GetEnvironmentVariable("PROGRAMFILES(x86)") 
        };

        static Dictionary<string, string[]> browserPatterns = new Dictionary<string, string[]>
        {
            { "Chrome", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA"), "Google\\Chrome\\User Data\\Default\\Network\\Cookies") } },
            { "Edge", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA"), "Microsoft\\Edge\\User Data\\Default\\Network\\Cookies") } },
            { "Firefox", new[] { Path.Combine(Environment.GetEnvironmentVariable("APPDATA"), "Mozilla\\Firefox\\Profiles\\*.default-release\\cookies.sqlite") } },
            { "Opera", new[] { Path.Combine(Environment.GetEnvironmentVariable("APPDATA"), "Opera Software\\Opera Stable\\Network\\Cookies") } },
            { "Brave", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA"), "BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies") } },
            { "Vivaldi", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA"), "Vivaldi\\User Data\\Default\\Network\\Cookies") } },
            { "UCBrowser", new[] { Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA"), "UCBrowser\\User Data\\Default\\Network\\Cookies") } },
            { "Tor", new[] { Path.Combine(Environment.GetEnvironmentVariable("APPDATA"), "Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\cookies.sqlite") } }
        };

        static string logFile = @"C:\logs\cookie_cleanup.log";
        static int intervalMinutes = 60;

        static void Main(string[] args)
        {
            if (!Directory.Exists(@"C:\logs"))
            {
                Directory.CreateDirectory(@"C:\logs");
            }

            Task.Run(() => RunCleanupCycle());
            Console.WriteLine("Cookie cleanup job started in the background.");
            Console.ReadLine(); // Keep the application running
        }

        static async Task RunCleanupCycle()
        {
            while (true)
            {
                Log($"Starting cleanup cycle...");

                CheckBrowserStatus();

                var cookieFiles = FindBrowserCookieFiles();
                foreach (var file in cookieFiles)
                {
                    var detectedCookies = DetectTrackingCookies(file);
                    if (detectedCookies.Count > 0)
                    {
                        Log($"Detected in {file.Browser}: {string.Join(", ", detectedCookies)}");
                        RemoveTrackingCookies(file.Path);
                    }
                    else
                    {
                        Log($"No tracking cookies in {file.Path}");
                    }
                }

                Log($"Cleanup cycle completed! Waiting {intervalMinutes} minutes...");
                await Task.Delay(TimeSpan.FromMinutes(intervalMinutes)); // Wait before the next run
            }
        }

        static void Log(string message)
        {
            File.AppendAllText(logFile, $"[{DateTime.Now}] {message}{Environment.NewLine}");
        }

        static void CheckBrowserStatus()
        {
            var browsers = new[] { "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "ucbrowser", "tor" };
            foreach (var browser in browsers)
            {
                var processes = System.Diagnostics.Process.GetProcessesByName(browser);
                if (processes.Any())
                {
                    Log($"Warning: {browser} is running. Deletion may fail.");
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
                    var resolvedPaths = Directory.GetFiles(Path.GetDirectoryName(pathPattern), Path.GetFileName(pathPattern), SearchOption.AllDirectories);
                    foreach (var path in resolvedPaths)
                    {
                        detectedPaths.Add(new DetectedCookieFile { Browser = pattern.Key, Path = path });
                    }
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
                Log($"Scanning: {cookieFile.Path}");

                // This can be enhanced with SQLite parsing (not implemented here)
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
                Log($"Backed up to: {backupPath}");

                try
                {
                    File.Delete(path);
                    Log($"Deleted: {path}");
                }
                catch (Exception ex)
                {
                    Log($"Failed to delete {path}: {ex.Message}");
                }
            }
        }
    }

    class DetectedCookieFile
    {
        public string Browser { get; set; }
        public string Path { get; set; }
    }
}
