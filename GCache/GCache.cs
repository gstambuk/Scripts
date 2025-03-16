using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Management;
using System.Runtime.Versioning;
using Serilog;

namespace GCache
{
    public static class Constants
    {
        public const string CONFIG_FILE = "cache_config.json";
        public const string LOG_FILE = "cache_manager.log";
        public static readonly HashSet<string> TARGET_EXTENSIONS = new HashSet<string> { ".exe", ".dll", ".sys", ".iso" };
        public const double DEFAULT_CACHE_PERCENT = 0.5;
        public const long MIN_CACHE_GB = 10;
        public const long MAX_CACHE_GB = 500;
    }

    public static class Logger
    {
        static Logger()
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.File(Constants.LOG_FILE, outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} - {Level:u3} - {Message}{NewLine}")
                .CreateLogger();
        }

        public static void Info(string message) => Log.Information(message);
        public static void Warning(string message) => Log.Warning(message);
        public static void Error(string message) => Log.Error(message);
        public static void Critical(string message) => Log.Fatal(message);
    }

    public class AutoCacheManager
    {
        private readonly double cachePercent;
        private readonly long minCacheBytes;
        private readonly long maxCacheBytes;
        private bool running = true;
        private List<string> hdds = new List<string>();
        private List<string> ssds = new List<string>();
        private string cacheDir = string.Empty;
        private string hddDir = string.Empty;
        private string ssdPath = string.Empty;
        private long cacheSizeBytes = 0;
        private Dictionary<string, string> cachedFiles = new Dictionary<string, string>();

        public AutoCacheManager(double cachePercent = Constants.DEFAULT_CACHE_PERCENT, 
                              long minGb = Constants.MIN_CACHE_GB, 
                              long maxGb = Constants.MAX_CACHE_GB)
        {
            this.cachePercent = cachePercent;
            this.minCacheBytes = minGb * (1024L * 1024 * 1024);
            this.maxCacheBytes = maxGb * (1024L * 1024 * 1024);
            DetectDrives();
            Directory.CreateDirectory(cacheDir);
            SetInitialCacheSize();
            LoadCache();
            Logger.Info($"Initialized with dynamic cache size: {cacheSizeBytes / (1024.0 * 1024 * 1024):F2} GB");
        }

        [SupportedOSPlatform("windows")]
        private void DetectDrives()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                string driveName = drive.Name;
                try
                {
                    var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_DiskDrive WHERE DeviceID = '{driveName.Replace("\\", "\\\\")}'");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string mediaType = obj["MediaType"]?.ToString() ?? "";
                        if (mediaType.Contains("SSD")) ssds.Add(driveName);
                        else hdds.Add(driveName);
                    }
                }
                catch (Exception e)
                {
                    Logger.Warning($"Could not determine type for {driveName}: {e.Message}");
                }
            }

            if (!ssds.Any() || !hdds.Any())
            {
                throw new Exception("No SSD or HDD detected!");
            }

            ssdPath = ssds[0]; 
            hddDir = hdds[0];  
            cacheDir = Path.Combine(ssdPath, "Cache"); 
        }

        private void SetInitialCacheSize()
        {
            var driveInfo = new DriveInfo(ssdPath);
            long freeSpaceBytes = driveInfo.AvailableFreeSpace;
            long proposedSize = (long)(freeSpaceBytes * cachePercent);
            cacheSizeBytes = Math.Max(minCacheBytes, Math.Min(maxCacheBytes, proposedSize));
        }

        private void LoadCache()
        {
            if (File.Exists(Constants.CONFIG_FILE))
            {
                try
                {
                    string json = File.ReadAllText(Constants.CONFIG_FILE);
                    cachedFiles = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                }
                catch (Exception e)
                {
                    Logger.Error($"Failed to load cache config: {e.Message}");
                }
            }
        }

        private void CacheFile(string filePath)
        {
            Logger.Info($"Caching file: {filePath}");
            string destPath = Path.Combine(cacheDir, Path.GetFileName(filePath));

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(destPath) ?? string.Empty);
                File.Copy(filePath, destPath, true);
                cachedFiles[filePath] = destPath;
                File.Delete(filePath);
                File.CreateSymbolicLink(filePath, destPath);
                Logger.Info($"Cached file {filePath} to SSD.");
            }
            catch (Exception e)
            {
                Logger.Error($"Failed to cache {filePath}: {e.Message}");
            }
        }

        private void CleanCache()
        {
            Logger.Info("Cleaning up cache...");
            foreach (var file in cachedFiles.Keys.ToList())
            {
                try
                {
                    File.Delete(cachedFiles[file]);
                    cachedFiles.Remove(file);
                }
                catch (Exception e)
                {
                    Logger.Error($"Error deleting cached file {file}: {e.Message}");
                }
            }
        }

        public void Run()
        {
            Logger.Info("GCache started");

            foreach (var file in Directory.EnumerateFiles(hddDir, "*.*", SearchOption.AllDirectories))
            {
                if (!running) break;
                if (Constants.TARGET_EXTENSIONS.Contains(Path.GetExtension(file).ToLower()))
                    CacheFile(file);
            }
            CleanCache();
            Logger.Info("Initial cache run completed");

            while (running)
            {
                Thread.Sleep(10000);
            }
        }

        public void Stop() => running = false;
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var cacheManager = new AutoCacheManager();
                cacheManager.Run();
            }
            catch (Exception e)
            {
                Logger.Critical($"GCache failed: {e.Message}");
                while (true) Thread.Sleep(10000);
            }
        }
    }
}
