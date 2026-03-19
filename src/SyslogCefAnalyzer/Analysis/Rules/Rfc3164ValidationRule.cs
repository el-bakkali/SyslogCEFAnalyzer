namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 3 — Validates RFC 3164 (BSD Syslog) message structure.
/// Checks: timestamp format, hostname presence, tag/message structure.
/// </summary>
public sealed class Rfc3164ValidationRule : IAnalysisRule
{
    public string Name => "RFC 3164 Validation";
    public string Category => "RFC 3164 (BSD Syslog)";

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();
        var rfc3164 = messages.Where(m => m.DetectedFormat == SyslogFormat.RFC3164).ToList();

        if (rfc3164.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "No RFC 3164 messages detected",
                Detail = "No BSD Syslog (RFC 3164) formatted messages found in the input."
            });
            return findings;
        }

        // Timestamp validation
        var noTimestamp = rfc3164.Where(m => m.Rfc3164Timestamp is null).ToList();
        var withTimestamp = rfc3164.Where(m => m.Rfc3164Timestamp is not null).ToList();

        if (noTimestamp.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{noTimestamp.Count} messages missing RFC 3164 timestamp",
                Detail = "RFC 3164 expects timestamp in 'Mmm dd HH:mm:ss' format (e.g., 'Jan  5 12:34:56'). Messages without timestamps may be difficult to correlate in Log Analytics.",
                Recommendation = "Configure the source device to include a timestamp in BSD format. Check rsyslog/syslog-ng template configuration.",
                RelatedMessageIndices = noTimestamp.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Hostname validation
        var noHostname = rfc3164.Where(m => m.Hostname is null).ToList();
        if (noHostname.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{noHostname.Count} messages missing hostname",
                Detail = "RFC 3164 messages should include a hostname after the timestamp. Without it, AMA may not correctly identify the source in the Syslog table's HostName column.",
                Recommendation = "Configure the source device to include hostname. In rsyslog, use template: \"<%PRI%>%timegenerated% %HOSTNAME% %syslogtag%%msg%\"",
                RelatedMessageIndices = noHostname.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Tag/AppName validation
        var noTag = rfc3164.Where(m => m.Tag is null && m.Message is not null).ToList();
        if (noTag.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"{noTag.Count} messages have no process tag",
                Detail = "Messages without a process tag (e.g., 'sshd[1234]:') will appear without ProcessName in Log Analytics.",
                RelatedMessageIndices = noTag.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Empty message body
        var emptyBody = rfc3164.Where(m => string.IsNullOrWhiteSpace(m.Message)).ToList();
        if (emptyBody.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{emptyBody.Count} messages have empty message body",
                Detail = "These messages have a header but no content. They may indicate a misconfigured syslog template.",
                Recommendation = "Check the syslog forwarding template to ensure the message body is included.",
                RelatedMessageIndices = emptyBody.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Validation errors from parser
        var withErrors = rfc3164.Where(m => m.ValidationErrors.Count > 0).ToList();
        if (withErrors.Count > 0)
        {
            var errorSummary = withErrors
                .SelectMany(m => m.ValidationErrors)
                .GroupBy(e => e)
                .OrderByDescending(g => g.Count())
                .Select(g => $"  {g.Key}: {g.Count()} messages")
                .ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Error,
                Title = $"{withErrors.Count} messages have RFC 3164 validation errors",
                Detail = string.Join("\n", errorSummary),
                Recommendation = "Fix the source device's syslog format to comply with RFC 3164.",
                RelatedMessageIndices = withErrors.Take(10).Select(m => m.Index).ToList()
            });
        }

        if (noTimestamp.Count == 0 && noHostname.Count == 0 && withErrors.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = $"All {rfc3164.Count} RFC 3164 messages are well-formed",
                Detail = "All messages have valid timestamps, hostnames, and message bodies."
            });
        }

        return findings;
    }
}
