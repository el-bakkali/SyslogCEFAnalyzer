namespace SyslogCEFAnalyzer.ViewModels;

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using SyslogCEFAnalyzer.Analysis;
using SyslogCEFAnalyzer.Models;
using SyslogCEFAnalyzer.Parsers;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly AnalysisEngine _engine = new();

    // Store all parsed messages for drill-down
    private List<SyslogMessage> _allMessages = [];

    public MainViewModel()
    {
        BrowseCommand = new RelayCommand(Browse);
        ExportCommand = new RelayCommand(ExportReport, () => Report is not null);
        ShowRelatedMessagesCommand = new RelayCommand<AnalysisFinding>(ShowRelatedMessages);
        ClearDetailCommand = new RelayCommand(() => { SelectedFinding = null; DetailMessages.Clear(); });
        FilterByFormatCommand = new RelayCommand<string>(FilterByFormat);
    }

    private string? _filePath;
    public string? FilePath { get => _filePath; set { _filePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasFile)); } }

    private AnalysisReport? _report;
    public AnalysisReport? Report { get => _report; set { _report = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasReport)); ((RelayCommand)ExportCommand).RaiseCanExecuteChanged(); } }

    private bool _isAnalyzing;
    public bool IsAnalyzing { get => _isAnalyzing; set { _isAnalyzing = value; OnPropertyChanged(); } }

    private string? _statusMessage;
    public string? StatusMessage { get => _statusMessage; set { _statusMessage = value; OnPropertyChanged(); } }

    private string? _errorMessage;
    public string? ErrorMessage { get => _errorMessage; set { _errorMessage = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasError)); } }

    // Drill-down support
    private AnalysisFinding? _selectedFinding;
    public AnalysisFinding? SelectedFinding
    {
        get => _selectedFinding;
        set { _selectedFinding = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasSelectedFinding)); }
    }

    public bool HasFile => FilePath is not null;
    public bool HasReport => Report is not null;
    public bool HasError => ErrorMessage is not null;
    public bool HasSelectedFinding => SelectedFinding is not null;

    public ObservableCollection<FindingGroup> GroupedFindings { get; } = [];

    // All messages for drill-down
    public ObservableCollection<SyslogMessage> SampleMessages { get; } = [];

    // Messages related to a selected finding (drill-down detail)
    public ObservableCollection<SyslogMessage> DetailMessages { get; } = [];

    public RelayCommand BrowseCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand<AnalysisFinding> ShowRelatedMessagesCommand { get; }
    public RelayCommand ClearDetailCommand { get; }
    public RelayCommand<string> FilterByFormatCommand { get; }

    private void Browse()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select Capture or Log File",
            Filter = "All supported (*.pcap;*.pcapng;*.log;*.txt;*.syslog)|*.pcap;*.pcapng;*.log;*.txt;*.syslog|Capture files (*.pcap;*.pcapng)|*.pcap;*.pcapng|Log files (*.log;*.txt;*.syslog)|*.log;*.txt;*.syslog|All files (*.*)|*.*",
            CheckFileExists = true
        };
        if (dlg.ShowDialog() == true)
            _ = LoadAndAnalyzeAsync(dlg.FileName);
    }

    public async Task LoadAndAnalyzeAsync(string path)
    {
        ErrorMessage = null;
        Report = null;
        SelectedFinding = null;
        GroupedFindings.Clear();
        SampleMessages.Clear();
        DetailMessages.Clear();
        _allMessages = [];
        FilePath = path;
        IsAnalyzing = true;
        StatusMessage = "Loading file…";

        try
        {
            // Security: validate file extension (OWASP input validation / CIS-16)
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (!AllowedFileTypes.IsAllowed(ext) && ext != ".*")
            {
                // For unknown extensions, try to auto-detect by checking file header
                using var probe = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] header = new byte[4];
                int read = probe.Read(header, 0, 4);
                if (read >= 4)
                {
                    uint magic = BitConverter.ToUInt32(header, 0);
                    bool isPcapMagic = magic is 0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1 or 0x0a0d0d0a;
                    if (!isPcapMagic)
                    {
                        ErrorMessage = $"Unsupported file extension '{ext}'. Supported: .pcap, .pcapng, .cap, .log, .txt, .syslog";
                        StatusMessage = "Analysis failed.";
                        return;
                    }
                }
            }

            // Security: validate path is not a device or special file (OWASP path traversal)
            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                ErrorMessage = "File not found.";
                StatusMessage = "Analysis failed.";
                return;
            }

            bool isPcap = AllowedFileTypes.IsPcap(ext);
            // Also detect pcap by magic if extension is ambiguous
            if (!isPcap && ext is not ".log" and not ".txt" and not ".syslog")
            {
                using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] hdr = new byte[4];
                if (fs.Read(hdr, 0, 4) >= 4)
                {
                    uint m = BitConverter.ToUInt32(hdr, 0);
                    isPcap = m is 0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1 or 0x0a0d0d0a;
                }
            }

            InputSource source = isPcap ? InputSource.PcapFile : InputSource.LogFile;
            StatusMessage = isPcap ? "Extracting syslog messages from pcap…" : "Parsing log file…";

            var (messages, report) = await Task.Run(() =>
            {
                List<SyslogMessage> msgs;
                List<string> parseWarnings = [];

                if (isPcap)
                {
                    var (pcapMsgs, warnings) = PcapSyslogExtractor.ExtractFromPcap(fullPath);
                    msgs = pcapMsgs;
                    parseWarnings = warnings;
                }
                else
                {
                    msgs = SyslogParser.ParseLogFile(fullPath);
                }

                var rpt = _engine.Analyze(fullPath, msgs, source, parseWarnings);
                return (msgs, rpt);
            });

            Report = report;
            _allMessages = messages;

            // Show all messages (no hard-coded 100 limit)
            foreach (var msg in messages)
                SampleMessages.Add(msg);

            var groups = report.Findings
                .GroupBy(f => f.Category)
                .Select(g => new FindingGroup(g.Key, g.ToList()))
                .ToList();
            foreach (var group in groups)
                GroupedFindings.Add(group);

            StatusMessage = $"Analysis complete — {report.TotalMessages:N0} messages, {report.Findings.Count} findings";
        }
        catch (InvalidDataException ex)
        {
            ErrorMessage = $"Invalid file: {ex.Message}";
            StatusMessage = "Analysis failed.";
        }
        catch (OutOfMemoryException)
        {
            ErrorMessage = "File too large — not enough memory to process.";
            StatusMessage = "Analysis failed.";
        }
        catch (UnauthorizedAccessException)
        {
            ErrorMessage = "Access denied — cannot read the specified file.";
            StatusMessage = "Analysis failed.";
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Analysis error: {ex}");
            ErrorMessage = "An unexpected error occurred during analysis.";
            StatusMessage = "Analysis failed.";
        }
        finally
        {
            IsAnalyzing = false;
        }
    }

    /// <summary>Drill-down: show messages related to a specific finding.</summary>
    private void ShowRelatedMessages(AnalysisFinding? finding)
    {
        if (finding is null) return;

        SelectedFinding = finding;
        DetailMessages.Clear();

        if (finding.RelatedMessageIndices.Count > 0)
        {
            // Show the specific related messages
            var indexSet = finding.RelatedMessageIndices.ToHashSet();
            foreach (var msg in _allMessages.Where(m => indexSet.Contains(m.Index)))
                DetailMessages.Add(msg);
        }
        else
        {
            // No specific indices — show messages matching the finding's category/rule
            var related = finding.Category switch
            {
                "Message Format" => _allMessages.Where(m => m.DetectedFormat == SyslogFormat.Invalid),
                "PRI Field" => _allMessages.Where(m => !m.PriValue.HasValue && m.DetectedFormat != SyslogFormat.Invalid),
                "RFC 3164 (BSD Syslog)" => _allMessages.Where(m => m.DetectedFormat == SyslogFormat.RFC3164 && m.HasIssues),
                "RFC 5424 (IETF Syslog)" => _allMessages.Where(m => m.DetectedFormat == SyslogFormat.RFC5424 && m.HasIssues),
                "CEF (Common Event Format)" => _allMessages.Where(m => m.DetectedFormat == SyslogFormat.CEF && m.HasIssues),
                _ => _allMessages.Where(m => m.HasIssues)
            };

            foreach (var msg in related.Take(200))
                DetailMessages.Add(msg);
        }

        StatusMessage = $"Showing {DetailMessages.Count} related message(s) for: {finding.Title}";
    }

    /// <summary>Filter drill-down by format type (e.g. clicked on RFC3164 count badge).</summary>
    private void FilterByFormat(string? format)
    {
        if (format is null) return;

        DetailMessages.Clear();
        SelectedFinding = null;

        SyslogFormat? targetFormat = format switch
        {
            "RFC3164" => SyslogFormat.RFC3164,
            "RFC5424" => SyslogFormat.RFC5424,
            "CEF" => SyslogFormat.CEF,
            "Invalid" => SyslogFormat.Invalid,
            _ => null
        };

        if (targetFormat is null) return;

        foreach (var msg in _allMessages.Where(m => m.DetectedFormat == targetFormat))
            DetailMessages.Add(msg);

        StatusMessage = $"Showing {DetailMessages.Count} {format} message(s)";
    }

    private async void ExportReport()
    {
        if (Report is null) return;
        var dlg = new SaveFileDialog
        {
            Title = "Export Analysis Report",
            Filter = "Text file (*.txt)|*.txt|Markdown (*.md)|*.md",
            FileName = $"SyslogCEF_Analysis_{Report.FileName}_{Report.AnalyzedAt:yyyyMMdd_HHmmss}"
        };
        if (dlg.ShowDialog() != true) return;

        bool md = dlg.FilterIndex == 2;
        StatusMessage = "Exporting report…";

        try
        {
            // Async export to avoid blocking UI
            await Task.Run(() =>
            {
                using var writer = new StreamWriter(dlg.FileName, false, Encoding.UTF8);
                WriteReport(writer, Report, md);
            });
            StatusMessage = $"Report exported to {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Export error: {ex}");
            StatusMessage = "Export failed.";
        }
    }

    private static void WriteReport(StreamWriter writer, AnalysisReport report, bool md)
    {
        string h1 = md ? "# " : "";
        string h2 = md ? "## " : "=== ";
        string bullet = md ? "- " : "  • ";

        writer.WriteLine($"{h1}Syslog/CEF Analysis Report");
        writer.WriteLine();
        writer.WriteLine($"File: {report.FileName}");
        writer.WriteLine($"Analyzed: {report.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        writer.WriteLine($"Source: {report.Source}");
        writer.WriteLine($"Total messages: {report.TotalMessages:N0}");
        writer.WriteLine($"RFC 3164: {report.Rfc3164Count} | RFC 5424: {report.Rfc5424Count} | CEF: {report.CefCount} | Invalid: {report.InvalidCount}");
        writer.WriteLine();

        if (report.ParseWarnings.Count > 0)
        {
            writer.WriteLine($"{h2}Parser Warnings");
            writer.WriteLine();
            foreach (var w in report.ParseWarnings)
                writer.WriteLine($"{bullet}{w}");
            writer.WriteLine();
        }

        var groups = report.Findings.GroupBy(f => f.Category);
        foreach (var group in groups)
        {
            writer.WriteLine($"{h2}{group.Key}");
            writer.WriteLine();
            foreach (var f in group)
            {
                string icon = f.Severity switch { Severity.Pass => "[PASS]", Severity.Info => "[INFO]", Severity.Warning => "[WARN]", Severity.Error => "[ERROR]", _ => "" };
                writer.WriteLine($"{icon} {f.Title}");
                writer.WriteLine(f.Detail);
                if (f.ComplianceTag is not null) writer.WriteLine($"{bullet}Compliance: {f.ComplianceTag}");
                if (f.Recommendation is not null) writer.WriteLine($"{bullet}Recommendation: {f.Recommendation}");
                if (f.WiresharkFilter is not null) writer.WriteLine($"{bullet}Wireshark filter: {(md ? $"`{f.WiresharkFilter}`" : f.WiresharkFilter)}");
                if (f.RelatedMessageIndices.Count > 0) writer.WriteLine($"{bullet}Affected message indices: {string.Join(", ", f.RelatedMessageIndices.Take(20))}");
                writer.WriteLine();
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed record FindingGroup(string Category, List<AnalysisFinding> Findings)
{
    public Severity WorstSeverity => Findings.Count > 0 ? Findings.Max(f => f.Severity) : Severity.Pass;
}
