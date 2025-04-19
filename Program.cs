using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.Data.Sqlite;
using System.Management;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;

namespace Antivirus
{
    class Program
    {
        private static NotifyIcon? trayIcon;
        private static string quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "Quarantine");
        private static string dbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "ScanHistory.db");
        private static string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "Logs");
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly string apiKey = "46219682e8f5d9ab59eebc93a442dab6a9577e33d1f6f3ed47720252782fd6a3"; // VirusTotal API key
        private static readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();

        [STAThread]
        static void Main()
        {
            try
            {
                Console.WriteLine("Starting Simple Antivirus...");
                Application.EnableVisualStyles();
                Console.WriteLine("Visual styles enabled.");
                Application.SetCompatibleTextRenderingDefault(false);
                Console.WriteLine("Compatible text rendering set.");

                InitializeDirectories();
                Console.WriteLine("Directories initialized.");
                InitializeDatabase();
                Console.WriteLine("Database initialized.");
                InitializeSystemTray();
                Console.WriteLine("System tray initialized.");
                InitializeFileSystemWatchers();
                Console.WriteLine("File system watchers initialized.");

                Application.Run();
                Console.WriteLine("Application running.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}\n{ex.StackTrace}");
                File.AppendAllText(Path.Combine(logPath, $"log_{DateTime.Now:yyyyMMdd}.txt"), 
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Error: {ex.Message}\n{ex.StackTrace}{Environment.NewLine}");
                MessageBox.Show($"Simple Antivirus failed to start: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                throw; // Keep for debugging
            }
        }

        private static void InitializeDirectories()
        {
            Directory.CreateDirectory(quarantinePath);
            Directory.CreateDirectory(logPath);
        }

        private static void InitializeDatabase()
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS ScanHistory (
                    FileHash TEXT PRIMARY KEY,
                    FilePath TEXT,
                    ScanResult TEXT,
                    ScanDate TEXT
                )";
            command.ExecuteNonQuery();
        }

        private static void InitializeSystemTray()
        {
            try
            {
                Icon icon;
                try
                {
                    // Load embedded icon resource
                    using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Antivirus.Autorun.ico");
                    if (stream == null)
                    {
                        throw new FileNotFoundException("Embedded resource 'Autorun.ico' not found.");
                    }
                    icon = new Icon(stream);
                    Log("Embedded icon loaded successfully.");
                }
                catch (Exception ex)
                {
                    Log($"Failed to load embedded icon: {ex.Message}. Using default icon.");
                    icon = SystemIcons.Application; // Fallback to default icon
                }

                trayIcon = new NotifyIcon
                {
                    Icon = icon,
                    Text = "Simple Antivirus",
                    Visible = true
                };

                var contextMenu = new ContextMenuStrip();
                contextMenu.Items.Add("View Logs", null, (s, e) => Process.Start("explorer.exe", logPath));
                contextMenu.Items.Add("Open Quarantine", null, (s, e) => Process.Start("explorer.exe", quarantinePath));
                contextMenu.Items.Add("Exit", null, (s, e) => Application.Exit());
                trayIcon.ContextMenuStrip = contextMenu;

                trayIcon.DoubleClick += (s, e) => Process.Start("explorer.exe", quarantinePath);
                Log("System tray initialized successfully.");
            }
            catch (Exception ex)
            {
                Log($"Failed to initialize system tray: {ex.Message}");
                MessageBox.Show($"System tray error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void InitializeFileSystemWatchers()
        {
            try
            {
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
                foreach (var drive in drives)
                {
                    Log($"Setting up watcher for drive: {drive.RootDirectory.FullName}");
                    var watcher = new FileSystemWatcher
                    {
                        Path = drive.RootDirectory.FullName,
                        Filter = "*.dll",
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite,
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true
                    };
                    watcher.Created += async (s, e) => await OnFileCreated(e.FullPath);
                    watchers.Add(watcher);
                }
                Log("File system watchers initialized.");
            }
            catch (Exception ex)
            {
                Log($"Failed to initialize file system watchers: {ex.Message}");
            }
        }

        private static async Task OnFileCreated(string filePath)
        {
            if (IsCriticalSystemFile(filePath)) return;

            try
            {
                Log($"Detected new DLL: {filePath}");
                bool isUnsigned = !IsFileSigned(filePath);
                string fileHash = CalculateFileHash(filePath);

                if (isUnsigned)
                {
                    Log($"Unsigned DLL detected: {filePath}");
                    await QuarantineFile(filePath, fileHash, "Unsigned DLL");
                    return;
                }

                if (!await IsFileScanned(fileHash))
                {
                    var scanResult = await ScanWithVirusTotal(filePath, fileHash);
                    if (scanResult?.IsMalicious == true)
                    {
                        await QuarantineFile(filePath, fileHash, "VirusTotal flagged as malicious");
                    }
                    await StoreScanResult(fileHash, filePath, scanResult?.Result ?? "Clean");
                }
            }
            catch (Exception ex)
            {
                Log($"Error processing {filePath}: {ex.Message}");
            }
        }

        private static bool IsCriticalSystemFile(string filePath)
        {
            var systemPaths = new[] { @"C:\Windows\", @"C:\Program Files\", @"C:\Program Files (x86)\" };
            return systemPaths.Any(path => filePath.StartsWith(path, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsFileSigned(string filePath)
{
    try
    {
        // Using X509CertificateLoader to load the certificate
        var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);

        var cert2 = new X509Certificate2(cert);  // Wrapping it in X509Certificate2
        var chain = new X509Chain
        {
            ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck }
        };

        bool isValid = chain.Build(cert2);
        Log($"Signature check for {filePath}: {(isValid ? "Valid" : "Invalid")} certificate chain. Issuer: {cert2.Issuer}");
        return isValid;
    }
    catch (Exception ex)
    {
        Log($"Signature check failed for {filePath}: {ex.Message}");
        return false;
    }
}


        private static string CalculateFileHash(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private static async Task<bool> IsFileScanned(string fileHash)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM ScanHistory WHERE FileHash = $hash";
            command.Parameters.AddWithValue("$hash", fileHash);
            var count = Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0);
            return count > 0;
        }

        private static async Task<VirusTotalResult?> ScanWithVirusTotal(string filePath, string fileHash)
        {
            try
            {
                httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
                var response = await httpClient.GetAsync($"https://www.virustotal.com/api/v3/files/{fileHash}");
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<VirusTotalResult>(json);
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // File not found in VirusTotal, upload it
                    using var form = new MultipartFormDataContent();
                    var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                    form.Add(fileContent, "file", Path.GetFileName(filePath));
                    response = await httpClient.PostAsync("https://www.virustotal.com/api/v3/files", form);
                    if (response.IsSuccessStatusCode)
                    {
                        var json = await response.Content.ReadAsStringAsync();
                        return JsonSerializer.Deserialize<VirusTotalResult>(json);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"VirusTotal scan error: {ex.Message}");
            }
            return null;
        }

        private static async Task StoreScanResult(string fileHash, string filePath, string scanResult)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO ScanHistory (FileHash, FilePath, ScanResult, ScanDate)
                VALUES ($hash, $path, $result, $date)";
            command.Parameters.AddWithValue("$hash", fileHash);
            command.Parameters.AddWithValue("$path", filePath);
            command.Parameters.AddWithValue("$result", scanResult);
            command.Parameters.AddWithValue("$date", DateTime.UtcNow.ToString("o"));
            await command.ExecuteNonQueryAsync();
        }

        private static async Task QuarantineFile(string filePath, string fileHash, string reason)
        {
            try
            {
                // Kill processes using the file
                var processes = GetProcessesUsingFile(filePath);
                foreach (var process in processes)
                {
                    if (!IsCriticalProcess(process))
                    {
                        process.Kill();
                        await Task.Delay(100); // Wait for process to terminate
                    }
                }

                // Take ownership and modify permissions
                TakeOwnership(filePath);
                RemoveInheritedPermissions(filePath);
                GrantAdminPermissions(filePath);

                // Move to quarantine
                var quarantineFilePath = Path.Combine(quarantinePath, $"{fileHash}_{Path.GetFileName(filePath)}");
                File.Move(filePath, quarantineFilePath);
                Log($"Quarantined {filePath} to {quarantineFilePath}. Reason: {reason}");

                // Restart affected applications
                foreach (var process in processes)
                {
                    if (process.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        Process.Start("explorer.exe");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Failed to quarantine {filePath}: {ex.Message}");
            }
        }

        private static List<Process> GetProcessesUsingFile(string filePath)
        {
            var processes = new List<Process>();
            try
            {
                var wmiQuery = $"SELECT * FROM Win32_Process WHERE ExecutablePath IS NOT NULL";
                using var searcher = new ManagementObjectSearcher(wmiQuery);
                foreach (ManagementObject obj in searcher.Get())
                {
                    var processId = Convert.ToInt32(obj["ProcessId"]);
                    var process = Process.GetProcessById(processId);
                    try
                    {
                        foreach (ProcessModule module in process.Modules)
                        {
                            if (module.FileName.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                            {
                                processes.Add(process);
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return processes;
        }

        private static bool IsCriticalProcess(Process process)
        {
            var criticalProcesses = new[] { "svchost", "csrss", "smss", "wininit", "services" };
            return criticalProcesses.Contains(process.ProcessName.ToLower());
        }

        private static void TakeOwnership(string filePath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "takeown",
                        Arguments = $"/F \"{filePath}\" /A",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
            }
            catch (Exception ex)
            {
                Log($"Failed to take ownership of {filePath}: {ex.Message}");
            }
        }

        private static void RemoveInheritedPermissions(string filePath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "icacls",
                        Arguments = $@"{filePath} /inheritance:d",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
            }
            catch (Exception ex)
            {
                Log($"Failed to remove inherited permissions for {filePath}: {ex.Message}");
            }
        }

        private static void GrantAdminPermissions(string filePath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "icacls",
                        Arguments = $@"{filePath} /grant Administrators:F",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
            }
            catch (Exception ex)
            {
                Log($"Failed to grant admin permissions for {filePath}: {ex.Message}");
            }
        }

        private static void Log(string message)
        {
            var logFile = Path.Combine(logPath, $"log_{DateTime.Now:yyyyMMdd}.txt");
            File.AppendAllText(logFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}");
        }
    }

    public class VirusTotalResult
    {
        public bool IsMalicious => Data?.Attributes?.LastAnalysisStats?.Malicious > 0;
        public string Result => IsMalicious ? "Malicious" : "Clean";

        public VirusTotalData? Data { get; set; }
    }

    public class VirusTotalData
    {
        public VirusTotalAttributes? Attributes { get; set; }
    }

    public class VirusTotalAttributes
    {
        public VirusTotalStats? LastAnalysisStats { get; set; }
    }

    public class VirusTotalStats
    {
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Undetected { get; set; }
        public int Harmless { get; set; }
    }
}
