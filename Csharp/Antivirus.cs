using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace SimpleAntivirus
{
    class Program
    {
        static string scriptPath = @"C:\Windows\Setup\Scripts\Antivirus.ps1";
        static string quarantineFolder = @"C:\Quarantine";
        static string localDatabase = @"C:\Quarantine\scanned_files.txt";
        static string virusTotalApiKey = "24ebf7780f869017f4bf596d11d6d38dc6dd37ec5a52494b3f0c65f3bdd2c929";
        static Dictionary<string, bool> scannedFiles = new Dictionary<string, bool>();

        static async Task Main(string[] args)
        {
            // Ensure the script is saved in a known location
            if (!File.Exists(scriptPath))
            {
                File.Copy(Environment.GetCommandLineArgs()[0], scriptPath, true);
            }

            // Create Quarantine Folder if it doesn't exist
            if (!Directory.Exists(quarantineFolder))
            {
                Directory.CreateDirectory(quarantineFolder);
            }

            // Load previously scanned files into the dictionary
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

            // Start the antivirus process
            await RunAntivirus();
        }

        static async Task RunAntivirus()
        {
            while (true)
            {
                await RemoveUnsignedDLLs();
                await ScanAllFilesWithVirusTotal();
                await Task.Delay(TimeSpan.FromMinutes(10));  // Run the scan periodically
            }
        }

        static async Task RemoveUnsignedDLLs()
        {
            var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
            foreach (var drive in drives)
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
        }

        static async Task ScanAllFilesWithVirusTotal()
        {
            var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
            foreach (var drive in drives)
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
                    Console.WriteLine($"Error scanning {fileHash} with VirusTotal");
                    return false;
                }
            }
        }

        static int ParseMaliciousCount(string response)
        {
            // You can use a JSON library like Newtonsoft.Json to parse the response and extract the malicious count
            // For simplicity, assuming response contains a key "malicious_count"
            var startIdx = response.IndexOf("malicious") + 11;
            var endIdx = response.IndexOf(",", startIdx);
            var maliciousCount = int.Parse(response.Substring(startIdx, endIdx - startIdx));
            return maliciousCount;
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
            var processes = Process.GetProcesses().Where(p => p.MainModule?.FileName == filePath);
            foreach (var process in processes)
            {
                process.Kill();
            }
        }

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
    }
}
