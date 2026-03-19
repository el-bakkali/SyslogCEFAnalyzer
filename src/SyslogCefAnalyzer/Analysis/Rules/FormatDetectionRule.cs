namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 1 — Format detection summary: how many RFC 3164, RFC 5424, CEF, and invalid messages.
/// </summary>
public sealed class FormatDetectionRule : IAnalysisRule
{
    public string Name => "Format Detection";
    public string Category => "Message Format";

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();
        if (messages.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Error,
                Title = "No syslog/CEF messages found",
                Detail = "No messages could be extracted from the input file. If this is a pcap, ensure it contains traffic on ports 514, 6514, or 28330.",
                Recommendation = "Verify the capture includes syslog traffic. For pcap, use Wireshark filter: udp.port == 514 || tcp.port == 514",
                WiresharkFilter = "udp.port == 514 || tcp.port == 514 || tcp.port == 28330"
            });
            return findings;
        }

        var groups = messages.GroupBy(m => m.DetectedFormat).ToDictionary(g => g.Key, g => g.ToList());
        int rfc3164 = groups.GetValueOrDefault(SyslogFormat.RFC3164)?.Count ?? 0;
        int rfc5424 = groups.GetValueOrDefault(SyslogFormat.RFC5424)?.Count ?? 0;
        int cef = groups.GetValueOrDefault(SyslogFormat.CEF)?.Count ?? 0;
        int invalid = groups.GetValueOrDefault(SyslogFormat.Invalid)?.Count ?? 0;

        findings.Add(new AnalysisFinding
        {
            RuleName = Name, Category = Category,
            Severity = invalid > messages.Count / 2 ? Severity.Error : invalid > 0 ? Severity.Warning : Severity.Pass,
            Title = $"Format breakdown: {rfc3164} RFC 3164, {rfc5424} RFC 5424, {cef} CEF, {invalid} Invalid",
            Detail = $"Total messages: {messages.Count}\n" +
                     $"RFC 3164 (BSD Syslog): {rfc3164} ({Pct(rfc3164, messages.Count)}%)\n" +
                     $"RFC 5424 (IETF Syslog): {rfc5424} ({Pct(rfc5424, messages.Count)}%)\n" +
                     $"CEF (Common Event Format): {cef} ({Pct(cef, messages.Count)}%)\n" +
                     $"Invalid / Unparseable: {invalid} ({Pct(invalid, messages.Count)}%)",
            Recommendation = invalid > 0 ? "Review invalid messages — they may be truncated, malformed, or in an unsupported format." : null
        });

        // AMA compatibility note
        if (rfc3164 > 0 || rfc5424 > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = "AMA-compatible syslog formats detected",
                Detail = "Azure Monitor Agent supports both RFC 3164 (BSD) and RFC 5424 (IETF) syslog formats."
            });
        }

        return findings;
    }

    private static int Pct(int count, int total) => total > 0 ? (int)Math.Round(100.0 * count / total) : 0;
}
