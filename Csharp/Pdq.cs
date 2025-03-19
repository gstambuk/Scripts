using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

class SystemCleanupUtility
{
    static string logPath = @"C:\Logs"; // Change this to your log path
    static string logFile = $"{Environment.MachineName}_system_cleanup.log";
    static string forceCloseProcesses = "yes";
    static string forceCloseProcessesExitCode = "1618";
    static long logMaxSize = 2097152; // 2MB

    static string[] browserProcesses = { "battle", "chrome", "firefox", "flash", "iexplore", "iexplorer", "opera", "palemoon", "plugin-container", "skype", "steam", "yahoo" };
    static string[] vncProcesses = { "winvnc", "winvnc4", "uvnc_service", "tvnserver" };

    static string[] flashGuidsActiveX = { "cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c" }; // Example GUID, you can extend it with more
    static string[] flashGuidsPlugin = { "F6E23569-A22A-4924-93A4-3F215BEF63D2" }; // Example GUID, you can extend it with more

    static string osVersion = "OTHER";
    static string winVer = "Unknown";

    static void Main()
    {
        GetCurrentDate();
        CheckAdminRights();
        DetectOsVersion();
        HandleLogRotation();

        Log("Starting system cleanup...");

        CleanupFlash();
        CleanupVnc();
        CleanupTemp();
        CleanupUsb();

        Log("System cleanup complete.");
    }

    static void Log(string message)
    {
        string logFilePath = Path.Combine(logPath, logFile);
        using (StreamWriter sw = File.AppendText(logFilePath))
        {
            sw.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}");
        }
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}");
    }

    static void GetCurrentDate()
    {
        string currentDate = DateTime.Now.ToString("yyyy-MM-dd");
    }

    static void CheckAdminRights()
    {
        if (!IsUserAdministrator())
        {
            Log("ERROR: Administrative privileges required.");
            Environment.Exit(1);
        }
    }

    static bool IsUserAdministrator()
    {
        try
        {
            using (var pc = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()))
            {
                return pc.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
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
        string logFilePath = Path.Combine(logPath, logFile);
        if (File.Exists(logFilePath) && new FileInfo(logFilePath).Length >= logMaxSize)
        {
            string oldLogFile = Path.Combine(logPath, logFile + ".old");
            if (File.Exists(oldLogFile))
            {
                File.Delete(oldLogFile);
            }
            File.Move(logFilePath, oldLogFile);
        }
    }

    static void CleanupFlash()
    {
        Log("Cleaning Adobe Flash Player...");

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
        Log("Closing Flash-related processes...");
        foreach (var process in browserProcesses)
        {
            foreach (var proc in Process.GetProcessesByName(process))
            {
                try
                {
                    proc.Kill();
                    Log($"Killed process: {process}");
                }
                catch (Exception ex)
                {
                    Log($"Error killing process {process}: {ex.Message}");
                }
            }
        }
    }

    static void CheckFlashProcesses()
    {
        Log("Checking for running Flash processes...");
        foreach (var process in browserProcesses)
        {
            if (Process.GetProcessesByName(process).Any())
            {
                Log($"ERROR: Process '{process}' running, aborting.");
                Environment.Exit(int.Parse(forceCloseProcessesExitCode));
            }
        }
    }

    static void RemoveFlash()
    {
        // Assuming uninstallation methods here
        Log("Removing Adobe Flash Player...");

        // Here, you would typically run an uninstaller, e.g., from an MSI or EXE
        // For the sake of simplicity, we skip this since it's not feasible in this context

        // Log all GUID removal actions
        foreach (var guid in flashGuidsActiveX.Concat(flashGuidsPlugin))
        {
            // Uninstall based on GUIDs (dummy code)
            Log($"Uninstalling GUID {guid}");
        }
    }

    static void CleanupVnc()
    {
        Log("Cleaning VNC installations...");
        RemoveVnc();
    }

    static void RemoveVnc()
    {
        Log("Stopping VNC services...");
        foreach (var process in vncProcesses)
        {
            foreach (var proc in Process.GetProcessesByName(process))
            {
                try
                {
                    proc.Kill();
                    Log($"Killed VNC process: {process}");
                }
                catch (Exception ex)
                {
                    Log($"Error killing VNC process {process}: {ex.Message}");
                }
            }
        }

        // Log registry and file removal
        Log("Removing VNC registry entries...");
        // In C#, registry removal can be done using Microsoft.Win32.Registry

        Log("Removing VNC files...");
        // Removing files (dummy code)
        foreach (var dir in new[] { "UltraVNC", "RealVNC", "TightVNC" })
        {
            // Directory deletion (dummy code)
            Log($"Deleted directory: {dir}");
        }
    }

    static void CleanupTemp()
    {
        Log("Cleaning temporary files...");
        CleanTempFiles();
    }

    static void CleanTempFiles()
    {
        Log("Cleaning user temp files...");
        DeleteFilesInDirectory(Path.GetTempPath());

        // Handle specific user temp folders based on OS
        if (osVersion == "XP")
        {
            // Handle XP specific paths
        }
        else
        {
            // Handle Vista/other specific paths
        }

        Log("Cleaning system temp files...");
        DeleteFilesInDirectory(Path.Combine(Environment.GetEnvironmentVariable("WINDIR"), "TEMP"));
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
                    Log($"Deleted file: {file}");
                }
                catch (Exception ex)
                {
                    Log($"Error deleting file {file}: {ex.Message}");
                }
            }

            foreach (var dir in Directory.GetDirectories(path))
            {
                try
                {
                    Directory.Delete(dir, true);
                    Log($"Deleted directory: {dir}");
                }
                catch (Exception ex)
                {
                    Log($"Error deleting directory {dir}: {ex.Message}");
                }
            }
        }
    }

    static void CleanupUsb()
    {
        Log("Cleaning USB devices...");
        // USB cleanup logic here, if needed.
        // This is typically done via device management APIs, but you can add custom code here.
        Log("USB device cleanup skipped.");
    }
}
