namespace SyslogCEFAnalyzer.Analysis;

using SyslogCEFAnalyzer.Analysis.Rules;
using SyslogCEFAnalyzer.Models;
using SyslogCEFAnalyzer.Parsers;

public sealed class AnalysisEngine
{
    private readonly List<IAnalysisRule> _rules =
    [
        new FormatDetectionRule(),
        new PriValidationRule(),
        new Rfc3164ValidationRule(),
        new Rfc5424ValidationRule(),
        new CefValidationRule(),
        new CiscoAsaFtdRule(),
        new MessageSizeRule(),
        new TransportAnalysisRule(),
    ];

    public AnalysisReport Analyze(string fileName, List<SyslogMessage> messages, InputSource source, List<string>? parseWarnings = null)
    {
        var report = new AnalysisReport
        {
            FileName = Path.GetFileName(fileName),
            AnalyzedAt = DateTime.UtcNow,
            Source = source,
            TotalMessages = messages.Count,
            Rfc3164Count = messages.Count(m => m.DetectedFormat == SyslogFormat.RFC3164),
            Rfc5424Count = messages.Count(m => m.DetectedFormat == SyslogFormat.RFC5424),
            CefCount = messages.Count(m => m.DetectedFormat == SyslogFormat.CEF),
            InvalidCount = messages.Count(m => m.DetectedFormat == SyslogFormat.Invalid),
            ParseWarnings = parseWarnings ?? []
        };

        // Surface parse warnings as findings (truncation, format issues)
        if (parseWarnings is { Count: > 0 })
        {
            report.Findings.Add(new AnalysisFinding
            {
                RuleName = "File Integrity",
                Category = "File Integrity",
                Severity = Severity.Warning,
                Title = $"{parseWarnings.Count} parser warning(s) detected",
                Detail = string.Join("\n", parseWarnings.Select(w => $"  • {w}")),
                Recommendation = "The input file may be truncated, corrupted, or incomplete. Re-capture or obtain a complete copy.",
                ComplianceTag = "NIST-DE.AE-3 | CIS-8.2"
            });
        }

        foreach (var rule in _rules)
        {
            try
            {
                var findings = rule.Analyze(messages);
                // Deduplicate findings with identical title+category
                foreach (var finding in findings)
                {
                    bool isDuplicate = report.Findings.Any(f =>
                        f.Title == finding.Title && f.Category == finding.Category);
                    if (!isDuplicate)
                        report.Findings.Add(finding);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[{rule.Name}] Exception: {ex}");
                report.Findings.Add(new AnalysisFinding
                {
                    RuleName = rule.Name,
                    Category = rule.Category,
                    Severity = Severity.Warning,
                    Title = $"Rule '{rule.Name}' encountered an error",
                    Detail = "An analysis rule failed to complete. The input file may be incomplete or corrupted."
                });
            }
        }

        return report;
    }
}
