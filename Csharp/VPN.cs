using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using Microsoft.Extensions.Logging;
using Serilog;

namespace GVpn
{
    class Program
    {
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        private static NotifyIcon _notifyIcon;
        private static string _currentVpnHost;
        private static CancellationTokenSource _cts;
        private static string logFilePath = "GVpn.log"; // Adjust path as necessary
        
        [STAThread]
        static async Task Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            SetupTrayIcon();
            
            _cts = new CancellationTokenSource();
            Task.Run(() => VpnMonitor(_cts.Token));
            Application.Run();
        }

        static void SetupTrayIcon()
        {
            _notifyIcon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Visible = true,
                ContextMenuStrip = new ContextMenuStrip()
            };

            _notifyIcon.ContextMenuStrip.Items.Add("Connect to another VPN", null, async (s, e) => await ReconnectVpn());
            _notifyIcon.ContextMenuStrip.Items.Add("Disconnect", null, (s, e) => DisconnectVpn());
            _notifyIcon.ContextMenuStrip.Items.Add("Open GVpn Log", null, (s, e) => OpenLogFile());
            _notifyIcon.ContextMenuStrip.Items.Add("Exit", null, (s, e) => ExitApp());
        }

        static async Task ReconnectVpn()
        {
            DisconnectVpn();
            await ConnectToBestVpn();
        }

        static async Task ConnectToBestVpn()
        {
            var (host, country) = await GetPublicVpn();
            if (!string.IsNullOrEmpty(host))
            {
                _currentVpnHost = host;
                ConnectVpn(host);
            }
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
                    return (bestServer[1], bestServer[2]);
                }
            }
            catch { }
            return (null, null);
        }

        static bool ConnectVpn(string host)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "rasdial",
                    Arguments = $"MyVPN {host} vpn vpn",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                return true;
            }
            catch { return false; }
        }

        static void DisconnectVpn()
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "rasdial",
                Arguments = "MyVPN /disconnect",
                CreateNoWindow = true,
                UseShellExecute = false
            });
        }

        static async Task VpnMonitor(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                if (!CheckVpn())
                {
                    await ConnectToBestVpn();
                }
                await Task.Delay(30000, token);
            }
        }

        static bool CheckVpn()
        {
            try
            {
                var output = Process.Start(new ProcessStartInfo
                {
                    FileName = "rasdial",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                })?.StandardOutput.ReadToEnd();

                return output?.Contains("Connected") == true;
            }
            catch { return false; }
        }

        static void ExitApp()
        {
            _cts.Cancel();
            _notifyIcon.Dispose();
            Application.Exit();
        }

        static void OpenLogFile()
        {
            try
            {
                if (File.Exists(logFilePath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = logFilePath,
                        UseShellExecute = true
                    });
                }
                else
                {
                    MessageBox.Show("Log file not found.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open log file: {ex.Message}");
            }
        }
    }
}