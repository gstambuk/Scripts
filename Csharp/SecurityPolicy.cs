using System;
using System.IO;
using System.Security.Principal;
using System.Diagnostics;

class Program
{
    static void Main()
    {
        HardenPrivilegeRights();
    }

    static void HardenPrivilegeRights()
    {
        // Ensure the program is run as Administrator
        if (!IsRunningAsAdministrator())
        {
            Console.WriteLine("This program must be run as an Administrator.");
            return;
        }

        // Privilege rights settings
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

        // Secure temp file path
        string cfgPath = Path.GetTempFileName();

        try
        {
            // Export current security policy
            ExecuteCommand("secedit", $"/export /cfg {cfgPath} /quiet");

            // Write new settings
            File.WriteAllText(cfgPath, privilegeSettings);

            // Apply new security policy
            ExecuteCommand("secedit", $"/configure /db c:\\windows\\security\\local.sdb /cfg {cfgPath} /areas USER_RIGHTS /quiet");

            Console.WriteLine("Privilege rights hardened successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error hardening privilege rights: {ex.Message}");
        }
        finally
        {
            // Clean up temp file
            if (File.Exists(cfgPath))
            {
                try
                {
                    File.Delete(cfgPath);
                }
                catch
                {
                    // Handle any errors during cleanup
                }
            }
        }
    }

    static bool IsRunningAsAdministrator()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static void ExecuteCommand(string command, string arguments)
    {
        var processStartInfo = new ProcessStartInfo
        {
            FileName = command,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        using (var process = Process.Start(processStartInfo))
        {
            process.WaitForExit();
        }
    }
}
