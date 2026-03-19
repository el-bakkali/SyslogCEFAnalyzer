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

    public MainViewModel()
    {
        BrowseCommand = new RelayCommand(Browse);
        ExportCommand = new RelayCommand(ExportReport, () => Report is not null);
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

    public bool HasFile => FilePath is not null;
    public bool HasReport => Report is not null;
    public bool HasError => ErrorMessage is not null;

    public ObservableCollection<FindingGroup> GroupedFindings { get; } = [];

    // Sample messages for display
    public ObservableCollection<SyslogMessage> SampleMessages { get; } = [];

    public RelayCommand BrowseCommand { get; }
    public RelayCommand ExportCommand { get; }

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
        GroupedFindings.Clear();
        SampleMessages.Clear();
        FilePath = path;
        IsAnalyzing = true;
        StatusMessage = "Loading file…";

        try
        {
            var ext = Path.GetExtension(path).ToLowerInvariant();
            bool isPcap = ext is ".pcap" or ".pcapng" or ".cap";
            InputSource source = isPcap ? InputSource.PcapFile : InputSource.LogFile;

            StatusMessage = isPcap ? "Extracting syslog messages from pcap…" : "Parsing log file…";

            var (messages, report) = await Task.Run(() =>
            {
                List<SyslogMessage> msgs;
                if (isPcap)
                    msgs = PcapSyslogExtractor.ExtractFromPcap(path);
                else
                    msgs = SyslogParser.ParseLogFile(path);

                var rpt = _engine.Analyze(path, msgs, source);
                return (msgs, rpt);
            });

            Report = report;

            // Show first 100 sample messages
            foreach (var msg in messages.Take(100))
                SampleMessages.Add(msg);

            var groups = report.Findings
                .GroupBy(f => f.Category)
                .Select(g => new FindingGroup(g.Key, g.ToList()))
                .ToList();
            foreach (var group in groups)
                GroupedFindings.Add(group);

            StatusMessage = $"Analysis complete — {report.TotalMessages:N0} messages, {report.Findings.Count} findings";
        }
        catch (InvalidDataException)
        {
            ErrorMessage = "Invalid file format. The file may be corrupted or unsupported.";
            StatusMessage = "Analysis failed.";
        }
        catch (OutOfMemoryException)
        {
            ErrorMessage = "File too large — not enough memory to process.";
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

    private void ExportReport()
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
        string content = FormatReport(Report, md);
        File.WriteAllText(dlg.FileName, content, Encoding.UTF8);
        StatusMessage = $"Report exported to {Path.GetFileName(dlg.FileName)}";
    }

    private static string FormatReport(AnalysisReport report, bool md)
    {
        var sb = new StringBuilder();
        string h1 = md ? "# " : "";
        string h2 = md ? "## " : "=== ";
        string bullet = md ? "- " : "  • ";

        sb.AppendLine($"{h1}Syslog/CEF Analysis Report");
        sb.AppendLine();
        sb.AppendLine($"File: {report.FileName}");
        sb.AppendLine($"Analyzed: {report.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Source: {report.Source}");
        sb.AppendLine($"Total messages: {report.TotalMessages:N0}");
        sb.AppendLine($"RFC 3164: {report.Rfc3164Count} | RFC 5424: {report.Rfc5424Count} | CEF: {report.CefCount} | Invalid: {report.InvalidCount}");
        sb.AppendLine();

        var groups = report.Findings.GroupBy(f => f.Category);
        foreach (var group in groups)
        {
            sb.AppendLine($"{h2}{group.Key}");
            sb.AppendLine();
            foreach (var f in group)
            {
                string icon = f.Severity switch { Severity.Pass => "[PASS]", Severity.Info => "[INFO]", Severity.Warning => "[WARN]", Severity.Error => "[ERROR]", _ => "" };
                sb.AppendLine($"{icon} {f.Title}");
                sb.AppendLine(f.Detail);
                if (f.Recommendation is not null) sb.AppendLine($"{bullet}Recommendation: {f.Recommendation}");
                if (f.WiresharkFilter is not null) sb.AppendLine($"{bullet}Wireshark filter: {(md ? $"`{f.WiresharkFilter}`" : f.WiresharkFilter)}");
                sb.AppendLine();
            }
        }
        return sb.ToString();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed record FindingGroup(string Category, List<AnalysisFinding> Findings)
{
    public Severity WorstSeverity => Findings.Count > 0 ? Findings.Max(f => f.Severity) : Severity.Pass;
}
