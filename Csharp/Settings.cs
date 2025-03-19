using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.ServiceProcess;
using System.Security.AccessControl;
using System.Security.Principal;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            // Group Policy reset
            DeleteDirectory("%WinDir%\\System32\\GroupPolicyUsers");
            DeleteDirectory("%WinDir%\\System32\\GroupPolicy");
            DeleteDirectory("%WinDir%\\SysWOW64\\GroupPolicyUsers");
            DeleteDirectory("%WinDir%\\SysWOW64\\GroupPolicy");

            // Run DISM to add WMIC capability
            RunCommand("DISM", "/Online /Add-Capability /CapabilityName:WMIC~~~~");

            // Remove Autopilot provisioning package
            RunPowerShellCommand("Uninstall-ProvisioningPackage -AllInstalledPackages");

            // Modify registry settings (Autopilot and others)
            ModifyRegistry("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverInstall\\Restrictions", "AllowUserDeviceClasses", "0");
            ModifyRegistry("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin", "2");

            // Example: Removing user account (equivalent to the 'net user' command in batch)
            RunCommand("net", "user \"UserName\" /delete");

            // Stop and disable services
            ManageService("SSDPSRV", "stop", "disabled");
            ManageService("upnphost", "stop", "disabled");

            // Modify file permissions (Example)
            SetPermissions(@"C:\path\to\folder");

            Console.WriteLine("Operations completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static void DeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
                Console.WriteLine($"Deleted directory: {path}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error deleting directory {path}: {ex.Message}");
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

            Process process = Process.Start(processStartInfo);
            process.WaitForExit();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error executing command: {command} {arguments}: {ex.Message}");
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

            Process process = Process.Start(processStartInfo);
            process.WaitForExit();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error executing PowerShell command: {command}: {ex.Message}");
        }
    }

    static void ModifyRegistry(string registryKey, string valueName, string valueData)
    {
        try
        {
            Registry.SetValue(registryKey, valueName, valueData);
            Console.WriteLine($"Modified registry: {registryKey}\\{valueName} = {valueData}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error modifying registry {registryKey}: {ex.Message}");
        }
    }

    static void ManageService(string serviceName, string action, string startType)
    {
        try
        {
            ServiceController service = new ServiceController(serviceName);
            if (action.ToLower() == "stop")
            {
                service.Stop();
            }

            service.StartType = (ServiceStartMode)Enum.Parse(typeof(ServiceStartMode), startType, true);
            Console.WriteLine($"Service {serviceName} {action}d and set to {startType}.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error managing service {serviceName}: {ex.Message}");
        }
    }

    static void SetPermissions(string directoryPath)
    {
        try
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
            DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();
            directorySecurity.AddAccessRule(new FileSystemAccessRule("Administrators", FileSystemRights.FullControl, AccessControlType.Allow));
            directoryInfo.SetAccessControl(directorySecurity);

            Console.WriteLine($"Permissions set for: {directoryPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error setting permissions for {directoryPath}: {ex.Message}");
        }
    }
}
