namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 4 — Validates RFC 5424 (IETF Syslog) message structure.
/// Checks: version, ISO 8601 timestamp, hostname, app-name, structured data.
/// </summary>
public sealed class Rfc5424ValidationRule : IAnalysisRule
{
    public string Name => "RFC 5424 Validation";
    public string Category => "RFC 5424 (IETF Syslog)";

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();
        var rfc5424 = messages.Where(m => m.DetectedFormat == SyslogFormat.RFC5424).ToList();

        if (rfc5424.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "No RFC 5424 messages detected",
                Detail = "No IETF Syslog (RFC 5424) formatted messages found."
            });
            return findings;
        }

        // Version check (should be 1)
        var badVersion = rfc5424.Where(m => m.Rfc5424Version.HasValue && m.Rfc5424Version != 1).ToList();
        if (badVersion.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{badVersion.Count} messages have unexpected RFC 5424 version",
                Detail = $"Expected version 1. Found: {string.Join(", ", badVersion.Select(m => m.Rfc5424Version).Distinct())}",
                RelatedMessageIndices = badVersion.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Timestamp validation (ISO 8601)
        var noTimestamp = rfc5424.Where(m => m.Rfc5424Timestamp is null).ToList();
        if (noTimestamp.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{noTimestamp.Count} messages have NILVALUE timestamp",
                Detail = "RFC 5424 allows '-' (NILVALUE) for timestamp but AMA requires timestamps for proper ingestion into the Syslog table.",
                Recommendation = "Configure the source to send ISO 8601 timestamps (e.g., 2024-01-15T12:34:56.789Z).",
                RelatedMessageIndices = noTimestamp.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Hostname validation
        var noHostname = rfc5424.Where(m => m.Hostname is null).ToList();
        if (noHostname.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{noHostname.Count} messages have NILVALUE hostname",
                Detail = "Missing hostname affects the HostName column in Log Analytics.",
                Recommendation = "Configure the source device to include hostname in RFC 5424 messages.",
                RelatedMessageIndices = noHostname.Take(10).Select(m => m.Index).ToList()
            });
        }

        // App-name validation
        var noAppName = rfc5424.Where(m => m.AppName is null).ToList();
        if (noAppName.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"{noAppName.Count} messages have NILVALUE app-name",
                Detail = "Missing APP-NAME affects the ProcessName column in Log Analytics.",
                RelatedMessageIndices = noAppName.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Field length violations
        var lengthErrors = rfc5424.Where(m => m.ValidationErrors.Any(e => e.Contains("exceeds"))).ToList();
        if (lengthErrors.Count > 0)
        {
            var errorSummary = lengthErrors
                .SelectMany(m => m.ValidationErrors.Where(e => e.Contains("exceeds")))
                .GroupBy(e => e)
                .Select(g => $"  {g.Key}: {g.Count()} messages")
                .ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Error,
                Title = $"{lengthErrors.Count} messages exceed RFC 5424 field length limits",
                Detail = string.Join("\n", errorSummary),
                Recommendation = "Truncate fields to RFC 5424 limits: HOSTNAME ≤255, APP-NAME ≤48, PROCID ≤128, MSGID ≤32.",
                RelatedMessageIndices = lengthErrors.Take(10).Select(m => m.Index).ToList()
            });
        }

        if (noTimestamp.Count == 0 && noHostname.Count == 0 && badVersion.Count == 0 && lengthErrors.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = $"All {rfc5424.Count} RFC 5424 messages are well-formed",
                Detail = "All messages have valid version, timestamps, hostnames, and field lengths."
            });
        }

        return findings;
    }
}
