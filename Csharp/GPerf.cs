using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace SystemTweaker
{
    class Program
    {
        static void Main(string[] args)
        {
            // Disable write cache on all disks
            DisableWriteCache();

            // Disable scheduled tasks related to customer experience improvement and diagnostics
            DisableScheduledTasks();

            // Modify power settings
            ModifyPowerSettings();

            // Disable hibernation
            DisableHibernation();

            // Disable dynamic tick and platform clock
            ModifyBootSettings();

            // Configure memory usage settings
            ConfigureMemoryUsage();

            // Modify USB and IDE controller settings
            ModifyControllerSettings();

            // Set system log settings
            SetSystemLogSettings();

            Console.WriteLine("System tweaks applied successfully!");
        }

        static void DisableWriteCache()
        {
            // Disable Write Cache for all disks
            var regKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum", true);
            if (regKey != null)
            {
                foreach (var subKeyName in regKey.GetSubKeyNames())
                {
                    var subKey = regKey.OpenSubKey(subKeyName + @"\Device Parameters\Disk", true);
                    if (subKey != null)
                    {
                        subKey.SetValue("UserWriteCacheSetting", 1, RegistryValueKind.DWord);
                    }
                }
            }
        }

        static void DisableScheduledTasks()
        {
            // List of scheduled tasks to disable
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
                Console.WriteLine($"Error disabling task {taskName}: {ex.Message}");
            }
        }

        static void ModifyPowerSettings()
        {
            try
            {
                // Disable hibernation
                Process.Start("powercfg", "/h off");

                // Set processor cool policy
                Process.Start("powercfg", "/setACvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1");
                Process.Start("powercfg", "/setDCvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1");

                // Set power scheme to current
                Process.Start("powercfg", "/setactive SCHEME_CURRENT");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error modifying power settings: {ex.Message}");
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
                Console.WriteLine($"Error disabling hibernation: {ex.Message}");
            }
        }

        static void ModifyBootSettings()
        {
            try
            {
                // Disable dynamic tick and platform clock
                Process.Start("bcdedit", "/set disabledynamictick yes");
                Process.Start("bcdedit", "/deletevalue useplatformclock");
                Process.Start("bcdedit", "/set useplatformtick yes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error modifying boot settings: {ex.Message}");
            }
        }

        static void ConfigureMemoryUsage()
        {
            try
            {
                // Configure memory usage and MFT settings
                Process.Start("fsutil", "behavior set memoryusage 2");
                Process.Start("fsutil", "behavior set mftzone 4");
                Process.Start("fsutil", "behavior set disablelastaccess 1");
                Process.Start("fsutil", "behavior set disabledeletenotify 0");
                Process.Start("fsutil", "behavior set encryptpagingfile 0");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error configuring memory usage: {ex.Message}");
            }
        }

        static void ModifyControllerSettings()
        {
            try
            {
                // Modify USB and IDE controller settings (Power Management, Interrupts, etc.)
                // These might need specific Registry keys to be found based on the system's hardware
                // Example:
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
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error modifying controller settings: {ex.Message}");
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
                Console.WriteLine($"Error modifying system log settings: {ex.Message}");
            }
        }
    }
}
