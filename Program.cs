using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net;
using System.Windows.Forms;
using System.Drawing;
using System.Reflection;
using System.Text.Json;

class Program
{
    private static NotifyIcon? trayIcon;
    private static bool realTimeProtectionEnabled = true;
    private static readonly string logFile = @"C:\antivirus_log.txt";
    private static readonly string ownerName = "Gorstak";

    // List of critical system DLLs to exclude from scanning/quarantine
    private static readonly HashSet<string> ExcludedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "shell32.dll",
        "shlwapi.dll",
        "comctl32.dll",
        "msvcrt.dll",
        "rpcrt4.dll",
        "sechost.dll",
        "sspicli.dll",
        "crypt32.dll",
        "wintrust.dll",
        "lsasrv.dll",
        "samlib.dll",
        "netapi32.dll"
    };

    [STAThread]
    static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // Setup tray icon synchronously to ensure immediate visibility
        SetupTrayIcon();

        // Start antivirus engine and system scan asynchronously
#pragma warning disable CS4014 // Suppress warning for intentional fire-and-forget task
        Task.Run(async () =>
        {
            WriteLog($"[INFO] Starting Simple Antivirus by {ownerName}...");
            try
            {
                await AntivirusEngine.StartAsync();
                trayIcon?.ShowBalloonTip(3000, "Simple Antivirus", "Antivirus engine started.", ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                WriteLog($"[ERROR] Failed to start antivirus engine: {ex.Message}");
            }
        });
#pragma warning restore CS4014

        Application.Run();
    }

    private static void SetupTrayIcon()
    {
        ContextMenuStrip contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add("Scan Now", null, async (s, e) => await AntivirusEngine.StartSystemScanAsync());
        contextMenu.Items.Add("Toggle Real-Time Protection", null, (s, e) => ToggleRealtimeProtection());
        contextMenu.Items.Add("View Log", null, (s, e) => Process.Start("notepad.exe", logFile));
        contextMenu.Items.Add("Open Quarantine", null, (s, e) => Process.Start("explorer.exe", AntivirusEngine.quarantineFolder));
        contextMenu.Items.Add("About", null, (s, e) => MessageBox.Show($"Simple Antivirus by {ownerName}", "About"));
        contextMenu.Items.Add("Exit", null, (s, e) => Application.Exit());

        Icon trayIconImage = SystemIcons.Shield;
        try
        {
            var resourceName = "Antivirus.Autorun.ico";
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
            if (stream != null)
            {
                trayIconImage = new Icon(stream);
                WriteLog("[INFO] Custom tray icon loaded successfully.");
            }
            else
            {
                WriteLog($"[WARNING] Embedded icon '{resourceName}' not found. Using default shield icon.");
            }
        }
        catch (Exception ex)
        {
            WriteLog($"[ERROR] Failed to load tray icon: {ex.Message}");
        }

        trayIcon = new NotifyIcon()
        {
            Icon = trayIconImage,
            Text = $"Simple Antivirus by {ownerName}",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        WriteLog("[INFO] Tray icon setup completed.");
    }

    private static void ToggleRealtimeProtection()
    {
        realTimeProtectionEnabled = !realTimeProtectionEnabled;
        string status = realTimeProtectionEnabled ? "enabled" : "disabled";
        trayIcon!.Text = $"Simple Antivirus by {ownerName} ({status})";
        trayIcon.ShowBalloonTip(1000, "Simple Antivirus", $"Real-time protection {status}.", ToolTipIcon.Info);
        AntivirusEngine.SetRealTimeProtection(realTimeProtectionEnabled);
        WriteLog($"[INFO] Real-time protection {status}.");
    }

    public static void WriteLog(string message)
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            File.AppendAllText(logFile, $"{timestamp} {message}\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to write to log: {ex.Message}");
        }
    }

    public static bool IsExcludedDll(string fileName) => ExcludedDlls.Contains(fileName);
}

public class AntivirusEngine
{
    public static readonly string baseFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus");
    public static readonly string quarantineFolder = Path.Combine(baseFolder, "Quarantine");
    private static readonly string localDatabase = Path.Combine(baseFolder, "local_database.dat");
    private static Dictionary<string, (bool Valid, bool FromVT)> scannedFiles = new();
    private static DateTime lastEventTime = DateTime.MinValue;
    private static readonly int minIntervalMs = 500;
    private static readonly byte[] dbKey = SHA256.HashData(Encoding.UTF8.GetBytes("some-super-secret-key"));
    private static List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
    private static bool realTimeProtectionEnabled = true;
    private static readonly Dictionary<string, DateTime> lastLoggedErrors = new Dictionary<string, DateTime>();
    // Rate limiting for VirusTotal
    private static int queriesPerMinute = 0;
    private static DateTime lastMinuteReset = DateTime.Now;
    private static int queriesPerDay = 0;
    private static DateTime lastDayReset = DateTime.Now;
    private static readonly int maxQueriesPerMinute = 4;
    private static readonly int maxQueriesPerDay = 500;
    private static readonly Queue<(string Path, DateTime Added)> vtQueue = new Queue<(string, DateTime)>();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, MoveFileFlags dwFlags);

    [Flags]
    private enum MoveFileFlags
    {
        MOVEFILE_REPLACE_EXISTING = 0x00000001,
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
    }

#pragma warning disable CS1998 // Suppress warning for async method without await
    public static async Task StartAsync()
    {
        Directory.CreateDirectory(baseFolder);
        Directory.CreateDirectory(quarantineFolder);
        LoadDatabase();
        SetupFileWatchers();

        // Show engine started notification immediately
        Program.WriteLog("[INFO] Antivirus engine initialized.");

        // Start system scan in the background
        _ = Task.Run(async () =>
        {
            try
            {
                await ScanAllFilesAsync();
            }
            catch (Exception ex)
            {
                Program.WriteLog($"[ERROR] Background system scan failed: {ex.Message}");
            }
        });
    }
#pragma warning restore CS1998

    public static void SetRealTimeProtection(bool enabled)
    {
        realTimeProtectionEnabled = enabled;
        foreach (var watcher in watchers)
        {
            watcher.EnableRaisingEvents = enabled;
        }
    }

    private static void SetupFileWatchers()
    {
        var startTime = DateTime.Now;
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            try
            {
                FileSystemWatcher watcher = new(drive.RootDirectory.FullName)
                {
                    Filter = "*.*",
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    EnableRaisingEvents = realTimeProtectionEnabled
                };

                watcher.Created += OnFileEvent;
                watcher.Changed += OnFileEvent;
                watchers.Add(watcher);
                Program.WriteLog($"[INFO] File watcher set up for {drive.Name}");
            }
            catch (Exception ex)
            {
                Program.WriteLog($"[ERROR] Failed to set up watcher for {drive.Name}: {ex.Message}");
            }
        }
        var duration = (DateTime.Now - startTime).TotalSeconds;
        Program.WriteLog($"[INFO] File watchers setup completed in {duration:F2} seconds.");
    }

    public static async Task StartSystemScanAsync()
    {
        await ScanAllFilesAsync();
    }

    private static async Task ScanAllFilesAsync()
    {
        Program.WriteLog("[INFO] Starting system-wide file scan...");

        var nonVtEntries = scannedFiles.Keys.Where(k => !scannedFiles[k].FromVT).ToList();
        foreach (var key in nonVtEntries)
        {
            scannedFiles.Remove(key);
        }

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            try
            {
                await Task.Run(() =>
                {
                    foreach (var file in Directory.EnumerateFiles(drive.RootDirectory.FullName, "*.*", SearchOption.AllDirectories))
                    {
                        string fileName = Path.GetFileName(file);
                        if (Program.IsExcludedDll(fileName))
                        {
                            Program.WriteLog($"[INFO] Skipping critical system file: {file}");
                            continue;
                        }

                        if (Path.GetExtension(file).Equals(".dll", StringComparison.OrdinalIgnoreCase))
                        {
                            ScanDll(file);
                        }
                        else
                        {
                            EnqueueVtScan(file);
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Program.WriteLog($"[WARNING] Could not scan drive {drive.Name}: {ex.Message}");
            }
        }
        Program.WriteLog("[INFO] System-wide file scan completed.");
    }

    private static void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (!realTimeProtectionEnabled) return;
        if ((DateTime.Now - lastEventTime).TotalMilliseconds < minIntervalMs) return;
        lastEventTime = DateTime.Now;

        if (!File.Exists(e.FullPath)) return;

        string fileName = Path.GetFileName(e.FullPath);
        if (Program.IsExcludedDll(fileName))
        {
            Program.WriteLog($"[INFO] Skipping critical system file: {e.FullPath}");
            return;
        }

        if (e.FullPath.StartsWith(quarantineFolder, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string ext = Path.GetExtension(e.FullPath).ToLower();
        if (ext == ".dll")
        {
            ScanDll(e.FullPath);
        }
        else
        {
            EnqueueVtScan(e.FullPath);
        }
    }

    private static void ScanDll(string path)
    {
        string fileName = Path.GetFileName(path);
        if (Program.IsExcludedDll(fileName))
        {
            Program.WriteLog($"[INFO] Skipping critical system file: {path}");
            return;
        }

        var hashInfo = CalculateFileHash(path);
        if (hashInfo == null)
        {
            Program.WriteLog($"[WARNING] Initial hash calculation failed for {path}, attempting to unlock...");
            TakeFileOwnership(path);
            KillProcessesUsingFile(path);
            hashInfo = CalculateFileHash(path);
            if (hashInfo == null)
            {
                Program.WriteLog($"[ERROR] Failed to calculate hash for {path} after unlock attempt.");
                return;
            }
        }

        Program.WriteLog($"[INFO] Scanning DLL: {path}, Hash: {hashInfo.Value.Hash}");

        bool isSigned = hashInfo.Value.Valid;
        if (!isSigned)
        {
            scannedFiles[hashInfo.Value.Hash] = (false, false);
            KillProcessesUsingFile(path);
            QuarantineFile(path);
            SaveDatabase();
            Program.WriteLog($"[ALERT] Unsigned DLL detected and quarantined: {path}");
        }
        else
        {
            EnqueueVtScan(path);
            scannedFiles[hashInfo.Value.Hash] = (true, false);
            SaveDatabase();
            Program.WriteLog($"[INFO] Signed DLL queued for VirusTotal scan: {path}");
        }
    }

    private static void EnqueueVtScan(string filePath)
    {
        lock (vtQueue)
        {
            var hashInfo = CalculateFileHash(filePath);
            if (hashInfo != null && !scannedFiles.ContainsKey(hashInfo.Value.Hash))
            {
                vtQueue.Enqueue((filePath, DateTime.Now));
                Program.WriteLog($"[INFO] Queued for VirusTotal scan: {filePath}");
            }
            else if (hashInfo == null)
            {
                Program.WriteLog($"[WARNING] Skipped VirusTotal scan for {filePath} due to hash calculation failure.");
            }
        }
    }

    private static async Task ProcessVtQueue()
    {
        while (true)
        {
            if ((DateTime.Now - lastMinuteReset).TotalMinutes >= 1)
            {
                queriesPerMinute = 0;
                lastMinuteReset = DateTime.Now;
            }
            if ((DateTime.Now - lastDayReset).TotalDays >= 1)
            {
                queriesPerDay = 0;
                lastDayReset = DateTime.Now;
            }

            (string Path, DateTime Added) item;
            lock (vtQueue)
            {
                if (vtQueue.Count == 0 || queriesPerMinute >= maxQueriesPerMinute || queriesPerDay >= maxQueriesPerDay)
                {
                    Thread.Sleep(1000);
                    continue;
                }
                item = vtQueue.Dequeue();
            }

            if ((DateTime.Now - item.Added).TotalDays > 7)
            {
                Program.WriteLog($"[INFO] Skipped expired queued scan: {item.Path}");
                continue;
            }

            queriesPerMinute++;
            queriesPerDay++;
            await ScanWithVirusTotal(item.Path);

            Thread.Sleep(15000);
        }
    }

    private static (string Hash, bool Valid)? CalculateFileHash(string filePath)
    {
        for (int i = 0; i < 3; i++)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                string hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
                bool valid = false;
#pragma warning disable SYSLIB0057 // Suppress obsolete warning for CreateFromSignedFile
                try
                {
                    var cert = X509Certificate.CreateFromSignedFile(filePath);
                    using var cert2 = new X509Certificate2(cert);
                    var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    valid = chain.Build(cert2);
                }
#pragma warning restore SYSLIB0057
                catch (CryptographicException) { } // File is not signed
                catch (IOException ex)
                {
                    Program.WriteLog($"[WARNING] IO error accessing {filePath}: {ex.Message}");
                }
                return (hash, valid);
            }
            catch (IOException ex) when (ex.Message.Contains("being used by another process"))
            {
                if (i == 2)
                {
                    LogLockedFileError(filePath, ex.Message);
                    return null;
                }
                Thread.Sleep(500);
            }
            catch (Exception ex)
            {
                Program.WriteLog($"[ERROR] Error calculating hash for {filePath}: {ex.Message}");
                return null;
            }
        }
        return null;
    }

    private static void LogLockedFileError(string filePath, string message)
    {
        if (lastLoggedErrors.TryGetValue(filePath, out var lastLogged) && (DateTime.Now - lastLogged).TotalSeconds < 60)
        {
            return;
        }
        Program.WriteLog($"[WARNING] Could not access {filePath} to calculate hash: {message}");
        lastLoggedErrors[filePath] = DateTime.Now;
    }

    private static async Task ScanWithVirusTotal(string filePath)
    {
        var hashInfo = CalculateFileHash(filePath);
        if (hashInfo == null)
        {
            Program.WriteLog($"[WARNING] Initial hash calculation failed for {filePath}, attempting to unlock...");
            TakeFileOwnership(filePath);
            KillProcessesUsingFile(filePath);
            hashInfo = CalculateFileHash(filePath);
            if (hashInfo == null)
            {
                Program.WriteLog($"[ERROR] Failed to calculate hash for {filePath} after unlock attempt. Skipping quarantine.");
                return;
            }
        }

        if (scannedFiles.ContainsKey(hashInfo.Value.Hash))
        {
            Program.WriteLog($"[INFO] Skipping VirusTotal scan for {filePath}: already scanned.");
            return;
        }

        Program.WriteLog($"[INFO] Scanning with VirusTotal: {filePath}, Hash: {hashInfo.Value.Hash}");
        bool flagged;
        try
        {
            flagged = await VirusTotalAPI.CheckFileAsync(hashInfo.Value.Hash, filePath);
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] VirusTotal scan failed for {filePath}: {ex.Message}. Treating as safe.");
            flagged = false;
        }

        scannedFiles[hashInfo.Value.Hash] = (!flagged, true);
        SaveDatabase();

        if (flagged)
        {
            Program.WriteLog($"[ALERT] File flagged by VirusTotal: {filePath}. Moving to quarantine.");
            KillProcessesUsingFile(filePath);
            QuarantineFile(filePath);
        }
        else
        {
            Program.WriteLog($"[INFO] File cleared by VirusTotal: {filePath}. No action taken.");
        }
    }

    private static void KillProcessesUsingFile(string filePath)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.ProcessName.Equals("System", StringComparison.OrdinalIgnoreCase) ||
                        proc.ProcessName.Equals("smss", StringComparison.OrdinalIgnoreCase) ||
                        proc.ProcessName.Equals("csrss", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    foreach (ProcessModule module in proc.Modules)
                    {
                        if (string.Equals(module.FileName, filePath, StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                if (proc.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                                {
                                    proc.Kill();
                                    Process.Start("explorer.exe");
                                    Program.WriteLog($"[INFO] Restarted explorer.exe after closing for {filePath}");
                                }
                                else
                                {
                                    proc.Kill();
                                    Program.WriteLog($"[INFO] Killed process using {filePath}: {proc.ProcessName}");
                                }
                                Thread.Sleep(100);
                            }
                            catch (Exception ex)
                            {
                                Program.WriteLog($"[ERROR] Failed to kill process {proc.ProcessName} using {filePath}: {ex.Message}");
                            }
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Program.WriteLog($"[ERROR] Error enumerating modules for process {proc.ProcessName}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Error in KillProcessesUsingFile for {filePath}: {ex.Message}");
        }
    }

    private static void QuarantineFile(string filePath)
    {
        try
        {
            string fileName = Path.GetFileName(filePath);
            string dest = Path.Combine(quarantineFolder, $"{fileName}.quar_{DateTime.Now.Ticks}");

            bool isLocked = true;
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    using (File.Open(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    {
                        isLocked = false;
                        break;
                    }
                }
                catch
                {
                    Thread.Sleep(500);
                }
            }

            if (isLocked)
            {
                Program.WriteLog($"[WARNING] File {filePath} is locked, attempting to take ownership.");
                TakeFileOwnership(filePath);
                KillProcessesUsingFile(filePath);
            }

            File.Move(filePath, dest);
            Program.WriteLog($"[INFO] File moved to quarantine: {filePath} -> {dest}");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to move {filePath} to quarantine: {ex.Message}");
            try
            {
                TakeFileOwnership(filePath);
                if (!MoveFileEx(filePath, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT))
                {
                    Program.WriteLog($"[ERROR] Failed to schedule {filePath} for deletion on reboot.");
                }
                else
                {
                    Program.WriteLog($"[INFO] File {filePath} scheduled for deletion on reboot.");
                }
            }
            catch (Exception ex2)
            {
                Program.WriteLog($"[ERROR] Failed to schedule deletion for {filePath}: {ex2.Message}");
            }
        }
    }

    private static void TakeFileOwnership(string filePath)
    {
        try
        {
            var takeownInfo = new ProcessStartInfo
            {
                FileName = "takeown",
                Arguments = $"/f \"{filePath}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var takeown = Process.Start(takeownInfo);
            if (takeown == null)
            {
                Program.WriteLog($"[ERROR] Failed to start takeown process for {filePath}.");
                return;
            }
            takeown.WaitForExit();
            Program.WriteLog($"[INFO] Took ownership of {filePath}: {takeown.StandardOutput.ReadToEnd()}");

            var icaclsInfo = new ProcessStartInfo
            {
                FileName = "icacls",
                Arguments = $"\"{filePath}\" /grant Administrators:F",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var icacls = Process.Start(icaclsInfo);
            if (icacls == null)
            {
                Program.WriteLog($"[ERROR] Failed to start icacls process for {filePath}.");
                return;
            }
            icacls.WaitForExit();
            Program.WriteLog($"[INFO] Granted full control to {filePath}: {icacls.StandardOutput.ReadToEnd()}");

            var icaclsTrustedInfo = new ProcessStartInfo
            {
                FileName = "icacls",
                Arguments = $"\"{filePath}\" /setowner \"NT Service\\TrustedInstaller\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var icaclsTrusted = Process.Start(icaclsTrustedInfo);
            if (icaclsTrusted == null)
            {
                Program.WriteLog($"[ERROR] Failed to start icacls process to restore TrustedInstaller for {filePath}.");
                return;
            }
            icaclsTrusted.WaitForExit();
            Program.WriteLog($"[INFO] Restored TrustedInstaller ownership for {filePath}: {icaclsTrusted.StandardOutput.ReadToEnd()}");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to take ownership of {filePath}: {ex.Message}");
        }
    }

    private static void LoadDatabase()
    {
        try
        {
            if (!File.Exists(localDatabase)) return;
            var lines = File.ReadAllBytes(localDatabase);
            string decrypted = Encoding.UTF8.GetString(ProtectedData.Unprotect(lines, dbKey, DataProtectionScope.CurrentUser));
            foreach (var line in decrypted.Split('\n'))
            {
                var parts = line.Split(',');
                if (parts.Length == 3)
                    scannedFiles[parts[0]] = (bool.Parse(parts[1]), bool.Parse(parts[2]));
            }
            Program.WriteLog("[INFO] Local database loaded successfully.");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to load local database: {ex.Message}");
        }
    }

    private static void SaveDatabase()
    {
        try
        {
            var sb = new StringBuilder();
            foreach (var kvp in scannedFiles)
                sb.AppendLine($"{kvp.Key},{kvp.Value.Valid},{kvp.Value.FromVT}");
            byte[] encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(sb.ToString()), dbKey, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(localDatabase, encrypted);
            Program.WriteLog("[INFO] Local database saved successfully.");
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] Failed to save local database: {ex.Message}");
        }
    }
}

public static class VirusTotalAPI
{
    private const string ApiKey = "b2b90f8df9d89f4bba576642326738bec2f83fa5c2d5314838993d5cd8b3a175";

    public static async Task<bool> CheckFileAsync(string hash, string filePath)
    {
        try
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-apikey", ApiKey);

            Program.WriteLog($"[DEBUG] Sending VirusTotal request for {filePath}, hash: {hash}");
            var resp = await client.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}");
            Program.WriteLog($"[DEBUG] VirusTotal response status for {filePath}: {resp.StatusCode}");

            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync();
                Program.WriteLog($"[DEBUG] VirusTotal response for {filePath}: {(json.Length > 100 ? json.Substring(0, 100) + "..." : json)}");

                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("data", out var data) &&
                    data.TryGetProperty("attributes", out var attributes) &&
                    attributes.TryGetProperty("last_analysis_stats", out var stats))
                {
                    int malicious = stats.GetProperty("malicious").GetInt32();
                    int suspicious = stats.GetProperty("suspicious").GetInt32();
                    Program.WriteLog($"[DEBUG] VirusTotal stats for {filePath}: malicious={malicious}, suspicious={suspicious}");
                    return malicious > 0 || suspicious > 0;
                }
                else
                {
                    Program.WriteLog($"[WARNING] Invalid VirusTotal response format for {filePath}. Treating as safe.");
                    return false;
                }
            }
            else if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                Program.WriteLog($"[INFO] Hash not found in VirusTotal for {filePath}. Uploading file.");
                using var fs = File.OpenRead(filePath);
                var form = new MultipartFormDataContent();
                form.Add(new StreamContent(fs), "file", Path.GetFileName(filePath));
                var uploadResp = await client.PostAsync("https://www.virustotal.com/api/v3/files", form);
                Program.WriteLog($"[DEBUG] VirusTotal upload response for {filePath}: {uploadResp.StatusCode}");
                return false; // New uploads need analysis time, treat as safe for now
            }
            else
            {
                Program.WriteLog($"[WARNING] VirusTotal request failed for {filePath}: Status {resp.StatusCode}. Treating as safe.");
                return false;
            }
        }
        catch (Exception ex)
        {
            Program.WriteLog($"[ERROR] VirusTotal scan failed for {filePath}: {ex.Message}. Treating as safe.");
            return false;
        }
    }
}