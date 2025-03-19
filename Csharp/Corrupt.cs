using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static void Main(string[] args)
    {
        // Start the telemetry corruption task in a background thread
        Task.Run(() => CorruptTelemetry());

        // Optional: Keep the console open to monitor the task
        Console.WriteLine("Telemetry corruption task is running in the background. Press Enter to exit.");
        Console.ReadLine();
    }

    static void CorruptTelemetry()
    {
        // Expanded list of target telemetry files
        var targetFiles = new List<string>
        {
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\Microsoft\Windows\WebCache\WebCacheV01.dat",
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
            $@"{Environment.GetFolderPath(Environment.SpecialFolder.SystemRoot)}\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
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

        while (true)
        {
            var startTime = DateTime.Now;

            // Process each file or wildcard path
            foreach (var file in targetFiles)
            {
                if (file.Contains("*"))
                {
                    // Handle wildcard paths
                    var files = Directory.GetFiles(Path.GetDirectoryName(file), Path.GetFileName(file));
                    foreach (var f in files)
                    {
                        OverwriteFile(f);
                    }
                }
                else
                {
                    OverwriteFile(file);
                }
            }

            // Calculate elapsed time and sleep until the next hour
            var elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
            var sleepSeconds = Math.Max(3600 - elapsedSeconds, 0);
            Console.WriteLine($"Completed run at {DateTime.Now}. Sleeping for {sleepSeconds} seconds until next hour...");
            Thread.Sleep((int)sleepSeconds * 1000);
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
                File.WriteAllBytes(filePath, junk);
                Console.WriteLine($"Overwrote telemetry file: {filePath}");
            }
            else
            {
                Console.WriteLine($"File not found: {filePath}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error overwriting {filePath}: {ex.Message}");
        }
    }
}