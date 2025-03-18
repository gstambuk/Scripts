using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

public class GSecurity
{
    private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    private static readonly string _quarantineFolder = "C:\\Quarantine";
    private static readonly string _localDatabase = "C:\\Quarantine\\scanned_files.txt";
    private static readonly string _virusTotalApiKey = "24ebf7780f869017f4bf596d11d6d38dc6dd37ec5a52494b3f0c65f3bdd2c929";
    private static readonly Dictionary<string, bool> _scannedFiles = new Dictionary<string, bool>();
    
    static GSecurity()
    {
        Directory.CreateDirectory(_quarantineFolder);
        if (File.Exists(_localDatabase))
        {
            foreach (var line in File.ReadLines(_localDatabase))
            {
                var parts = line.Split(',');
                if (parts.Length == 2)
                    _scannedFiles[parts[0]] = bool.Parse(parts[1]);
            }
        }
    }
    
    public static void RemoveUnsignedDLLs()
    {
        var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
        foreach (var drive in drives)
        {
            var dlls = Directory.GetFiles(drive.RootDirectory.FullName, "*.dll", SearchOption.AllDirectories);
            foreach (var dll in dlls)
            {
                try
                {
                    var cert = new X509Certificate2(dll);
                    using (var chain = new X509Chain())
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        bool isValid = chain.Build(cert);
                        if (!isValid)
                        {
                            KillProcessUsingFile(dll);
                            QuarantineFile(dll);
                        }
                    }
                }
                catch
                {
                    KillProcessUsingFile(dll);
                    QuarantineFile(dll);
                }
            }
        }
    }

    public static async Task ScanAllFilesWithVirusTotal()
    {
        var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
        foreach (var drive in drives)
        {
            var files = Directory.GetFiles(drive.RootDirectory.FullName, "*.*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                string hash = CalculateFileHash(file);
                if (_scannedFiles.ContainsKey(hash)) continue;
                bool isMalicious = await ScanFileWithVirusTotal(hash);
                _scannedFiles[hash] = !isMalicious;
                File.AppendAllText(_localDatabase, $"{hash},{!isMalicious}\n");
                if (isMalicious)
                {
                    KillProcessUsingFile(file);
                    QuarantineFile(file);
                }
            }
        }
    }

    private static async Task<bool> ScanFileWithVirusTotal(string fileHash)
    {
        string url = $"https://www.virustotal.com/api/v3/files/{fileHash}";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("x-apikey", _virusTotalApiKey);
        var response = await _httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode) return false;
        var json = JObject.Parse(await response.Content.ReadAsStringAsync());
        int maliciousCount = json["data"]?["attributes"]?["last_analysis_stats"]?["malicious"]?.ToObject<int>() ?? 0;
        return maliciousCount > 3;
    }

    private static string CalculateFileHash(string filePath)
    {
        using (var sha256 = SHA256.Create())
        using (var stream = File.OpenRead(filePath))
        {
            return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
    }

    private static void QuarantineFile(string filePath)
    {
        Directory.CreateDirectory(_quarantineFolder);
        string quarantinePath = Path.Combine(_quarantineFolder, Path.GetFileName(filePath));
        File.Move(filePath, quarantinePath);
    }

    private static void KillProcessUsingFile(string filePath)
    {
        var processes = Process.GetProcesses().Where(p =>
        {
            try { return p.MainModule?.FileName == filePath; } catch { return false; }
        });
        foreach (var process in processes)
        {
            process.Kill();
        }
    }
}
