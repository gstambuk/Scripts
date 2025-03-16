using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Serilog;

namespace VpnApp
{
    class Program
    {
        private static readonly ILogger<Program> _logger;
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

        static Program()
        {
            // Configure logging using Serilog
            Log.Logger = new LoggerConfiguration()
                .WriteTo.File("vpn.log", rollingInterval: RollingInterval.Day)
                .CreateLogger();

            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddSerilog();
            });

            _logger = loggerFactory.CreateLogger<Program>();
        }

        static async Task Main(string[] args)
        {
            if (!OperatingSystem.IsWindows())
            {
                _logger.LogError("Non-Windows OS detected");
                return;
            }

            await InstallMissingPackages();
            _logger.LogInformation("Application started");

            var cts = new CancellationTokenSource();
            var monitorTask = Task.Run(() => VpnMonitor(cts.Token));

            try
            {
                await Task.Delay(Timeout.Infinite, cts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("User interrupted the application");
                if (CheckVpn())
                {
                    DisconnectVpn();
                }
                cts.Cancel();
                _logger.LogInformation("Application terminated");
            }
        }

        static Task InstallMissingPackages()
        {
            _logger.LogInformation("Required packages are already part of .NET runtime");
            return Task.CompletedTask;
        }

        static async Task<(string Host, string Country)> GetPublicVpn()
        {
            try
            {
                var response = await _httpClient.GetStringAsync("https://www.vpngate.net/api/iphone/");
                var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                var servers = lines
                    .Where(line => line.Contains(',') && line.Split(',').Length > 6)
                    .Select(line => line.Split(','))
                    .Skip(1)
                    .OrderBy(x => int.TryParse(x[6], out int ping) ? ping : int.MaxValue)
                    .ToList();

                if (servers.Any())
                {
                    var bestServer = servers.First();
                    var host = bestServer[1];
                    var country = bestServer[2];
                    _logger.LogInformation($"Selected closest VPN server: {host} ({country}, ping: {bestServer[6]}ms)");
                    return (host, country);
                }

                _logger.LogWarning("No valid VPN servers available.");
                return (null, null);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError($"VPN fetch failed: {ex.Message}");
                return (null, null);
            }
        }

        static bool ConnectVpn(string host)
        {
            if (string.IsNullOrEmpty(host))
            {
                _logger.LogError("No VPN host provided.");
                return false;
            }

            _logger.LogInformation($"Connecting to VPN: {host}");
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "rasdial",
                        Arguments = $"MyVPN {host} vpn vpn",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit(10000); // 10-second timeout

                if (process.ExitCode != 0)
                {
                    var error = process.StandardError.ReadToEnd();
                    _logger.LogError($"VPN connection failed: {error}");
                    return false;
                }

                _logger.LogInformation($"VPN connected to {host}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"VPN connection error: {ex.Message}");
                return false;
            }
        }

        static bool DisconnectVpn()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "rasdial",
                        Arguments = "MyVPN disconnect",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    _logger.LogInformation("VPN disconnected");
                    return true;
                }

                var error = process.StandardError.ReadToEnd();
                _logger.LogError($"Disconnect failed: {error}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Disconnect error: {ex.Message}");
                return false;
            }
        }

        static bool CheckVpn()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "rasdial",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                bool isConnected = output.Contains("Connected");
                _logger.LogDebug($"VPN status check: {(isConnected ? "Connected" : "Disconnected")}");
                return isConnected;
            }
            catch (Exception ex)
            {
                _logger.LogError($"VPN status check failed: {ex.Message}");
                return false;
            }
        }

        static async Task VpnMonitor(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                if (!CheckVpn())
                {
                    var (host, country) = await GetPublicVpn();
                    if (!string.IsNullOrEmpty(host))
                    {
                        ConnectVpn(host);
                    }
                }
                await Task.Delay(30000, token); // Check every 30 seconds
            }
        }
    }
}
