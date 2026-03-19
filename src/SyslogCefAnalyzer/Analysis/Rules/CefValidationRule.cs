namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 5 — Validates CEF (Common Event Format) message structure.
/// Checks: CEF version, pipe count (exactly 7), required fields, severity values.
/// CEF messages go to the CommonSecurityLog table in Microsoft Sentinel.
/// </summary>
public sealed class CefValidationRule : IAnalysisRule
{
    public string Name => "CEF Validation";
    public string Category => "CEF (Common Event Format)";

    private static readonly HashSet<string> ValidSeverityStrings = new(StringComparer.OrdinalIgnoreCase)
    {
        "0","1","2","3","4","5","6","7","8","9","10",
        "Unknown","Low","Medium","High","Very-High"
    };

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();
        var cefMessages = messages.Where(m => m.DetectedFormat == SyslogFormat.CEF).ToList();

        if (cefMessages.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "No CEF messages detected",
                Detail = "No Common Event Format messages found. If you expected CEF, verify the source is formatting messages as 'CEF:0|vendor|product|version|classId|name|severity|extension'."
            });
            return findings;
        }

        // Pipe count validation (must have exactly 7 pipes for 8 fields)
        var badPipes = cefMessages.Where(m => m.Cef?.PipeCount != 7).ToList();
        if (badPipes.Count > 0)
        {
            var pipeCounts = badPipes.GroupBy(m => m.Cef?.PipeCount ?? 0)
                .Select(g => $"  {g.Key} pipes: {g.Count()} messages")
                .ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Error,
                Title = $"{badPipes.Count} CEF messages have incorrect pipe count",
                Detail = $"CEF requires exactly 7 pipe delimiters separating 8 header fields.\n{string.Join("\n", pipeCounts)}\n\nExpected format: CEF:version|vendor|product|deviceVersion|classId|name|severity|extension",
                Recommendation = "Check the source device's CEF output format. Ensure pipes in field values are escaped as \\|.",
                ComplianceTag = "OWASP-A03 | NIST-DE.AE-3 | ISO-27034-A.12",
                RelatedMessageIndices = badPipes.Take(10).Select(m => m.Index).ToList()
            });
        }

        // CEF version validation
        var badVersion = cefMessages.Where(m => m.Cef?.CefVersion is not (0 or 1)).ToList();
        if (badVersion.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{badVersion.Count} CEF messages have unexpected version",
                Detail = $"CEF version should be 0 (most common) or 1. Found: {string.Join(", ", badVersion.Select(m => m.Cef?.CefVersion?.ToString() ?? "null").Distinct())}",
                RelatedMessageIndices = badVersion.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Required field validation
        var emptyVendor = cefMessages.Where(m => string.IsNullOrWhiteSpace(m.Cef?.DeviceVendor)).ToList();
        var emptyProduct = cefMessages.Where(m => string.IsNullOrWhiteSpace(m.Cef?.DeviceProduct)).ToList();
        var emptyClassId = cefMessages.Where(m => string.IsNullOrWhiteSpace(m.Cef?.DeviceEventClassId)).ToList();
        var emptyName = cefMessages.Where(m => string.IsNullOrWhiteSpace(m.Cef?.Name)).ToList();

        if (emptyVendor.Count > 0 || emptyProduct.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Error,
                Title = "CEF messages missing required vendor/product fields",
                Detail = $"Empty DeviceVendor: {emptyVendor.Count}\nEmpty DeviceProduct: {emptyProduct.Count}\n\nThese fields are required and map to DeviceVendor/DeviceProduct columns in CommonSecurityLog.",
                Recommendation = "Configure the source device to include vendor and product names in CEF output.",
                ComplianceTag = "NIST-DE.AE-3 | CIS-8.2",
                RelatedMessageIndices = emptyVendor.Concat(emptyProduct).Take(10).Select(m => m.Index).Distinct().ToList()
            });
        }

        // Severity validation
        var badSeverity = cefMessages
            .Where(m => m.Cef?.Severity is not null && !ValidSeverityStrings.Contains(m.Cef.Severity))
            .ToList();

        if (badSeverity.Count > 0)
        {
            var examples = badSeverity.Select(m => m.Cef!.Severity).Distinct().Take(5).ToList();
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{badSeverity.Count} CEF messages have non-standard severity",
                Detail = $"CEF severity should be 0-10 (numeric) or Unknown/Low/Medium/High/Very-High.\nFound: {string.Join(", ", examples!)}",
                Recommendation = "Map source severity values to CEF standard: 0-3=Low, 4-6=Medium, 7-8=High, 9-10=Very-High.",
                RelatedMessageIndices = badSeverity.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Extension field analysis
        var withExtension = cefMessages.Where(m => !string.IsNullOrWhiteSpace(m.Cef?.Extension)).ToList();
        var noExtension = cefMessages.Where(m => string.IsNullOrWhiteSpace(m.Cef?.Extension)).ToList();

        // Surface CEF truncation as an explicit finding
        var truncatedExt = cefMessages.Where(m => m.ValidationWarnings.Any(w => w.Contains("CEF extension field truncated"))).ToList();
        if (truncatedExt.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{truncatedExt.Count} CEF messages have oversized extension fields (truncated for analysis)",
                Detail = "Extension fields exceed 8 KB. Data beyond 8 KB was not analyzed and may contain critical security context.",
                Recommendation = "Review source device logging verbosity. Large extensions may indicate multi-event concatenation or misconfigured output.",
                ComplianceTag = "NIST-DE.AE-3 | CIS-8.5",
                RelatedMessageIndices = truncatedExt.Take(10).Select(m => m.Index).ToList()
            });
        }

        if (noExtension.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"{noExtension.Count} CEF messages have no extension fields",
                Detail = "CEF extension fields (key=value pairs) provide additional context like source/destination IPs, ports, and URLs. Without them, the CommonSecurityLog entry will have minimal detail.",
                RelatedMessageIndices = noExtension.Take(10).Select(m => m.Index).ToList()
            });
        }

        // CEF extension key analysis
        if (withExtension.Count > 0)
        {
            var allKeys = withExtension
                .Where(m => m.Cef?.ExtensionFields.Count > 0)
                .SelectMany(m => m.Cef!.ExtensionFields.Keys)
                .GroupBy(k => k, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(15)
                .ToList();
            
            if (allKeys.Count > 0)
            {
                string keyDetail = string.Join("\n", allKeys.Select(g => $"  {g.Key}: {g.Count()} messages"));
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name, Category = Category, Severity = Severity.Info,
                    Title = $"Top CEF extension keys across {withExtension.Count} messages",
                    Detail = keyDetail
                });
            }
        }

        // Vendor/product summary
        var vendorProducts = cefMessages
            .Where(m => m.Cef is not null)
            .GroupBy(m => $"{m.Cef!.DeviceVendor}|{m.Cef.DeviceProduct}")
            .OrderByDescending(g => g.Count())
            .ToList();

        if (vendorProducts.Count > 0)
        {
            string summary = string.Join("\n", vendorProducts.Select(g =>
                $"  {g.Key.Replace('|', '/')}: {g.Count()} messages"));
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"CEF sources identified: {vendorProducts.Count} vendor/product combinations",
                Detail = summary
            });
        }

        // All good
        if (badPipes.Count == 0 && emptyVendor.Count == 0 && emptyProduct.Count == 0 && badVersion.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = $"All {cefMessages.Count} CEF messages have valid header structure",
                Detail = "All messages have correct pipe count, version, and required fields."
            });
        }

        return findings;
    }
}
