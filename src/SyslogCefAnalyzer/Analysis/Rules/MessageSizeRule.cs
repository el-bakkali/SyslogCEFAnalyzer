namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 6 — Checks message size and encoding issues.
/// UDP syslog has a practical limit of ~2048 bytes. TCP can be larger but AMA has limits.
/// Also checks for encoding issues (non-UTF-8, control characters).
/// </summary>
public sealed class MessageSizeRule : IAnalysisRule
{
    public string Name => "Message Size & Encoding";
    public string Category => "Message Size";

    private const int UdpMaxRecommended = 2048;
    private const int TcpWarningThreshold = 8192;

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();
        if (messages.Count == 0) return findings;

        // Size analysis
        var sizes = messages.Select(m => m.RawMessage.Length).ToList();
        int minSize = sizes.Min();
        int maxSize = sizes.Max();
        double avgSize = sizes.Average();

        findings.Add(new AnalysisFinding
        {
            RuleName = Name, Category = Category, Severity = Severity.Info,
            Title = $"Message sizes: min {minSize}, avg {avgSize:F0}, max {maxSize} bytes",
            Detail = $"Smallest message: {minSize} bytes\nAverage message: {avgSize:F0} bytes\nLargest message: {maxSize} bytes"
        });

        // UDP truncation risk
        var udpMessages = messages.Where(m => m.Protocol == "UDP").ToList();
        if (udpMessages.Count > 0)
        {
            var oversized = udpMessages.Where(m => m.RawMessage.Length > UdpMaxRecommended).ToList();
            if (oversized.Count > 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name, Category = Category, Severity = Severity.Warning,
                    Title = $"{oversized.Count} UDP messages exceed {UdpMaxRecommended} bytes",
                    Detail = $"UDP syslog messages over {UdpMaxRecommended} bytes may be truncated by network devices or the OS. Largest: {oversized.Max(m => m.RawMessage.Length)} bytes.",
                    Recommendation = "Switch to TCP (port 514) for reliable delivery of large messages, or reduce message size at the source.",
                    ComplianceTag = "NIST-PR.PT-4 | CIS-8.5",
                    WiresharkFilter = "udp.port == 514 && udp.length > 2048",
                    RelatedMessageIndices = oversized.Take(10).Select(m => m.Index).ToList()
                });
            }
        }

        // Large TCP messages
        var largeTcp = messages.Where(m => m.Protocol == "TCP" && m.RawMessage.Length > TcpWarningThreshold).ToList();
        if (largeTcp.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"{largeTcp.Count} TCP messages exceed {TcpWarningThreshold} bytes",
                Detail = $"Large messages may indicate verbose logging or multi-line messages being concatenated.",
                RelatedMessageIndices = largeTcp.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Non-printable / control characters (excluding common ones like \n \r \t)
        var withControlChars = messages
            .Where(m => m.RawMessage.Any(c => char.IsControl(c) && c is not '\n' and not '\r' and not '\t'))
            .ToList();

        if (withControlChars.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{withControlChars.Count} messages contain control characters",
                Detail = "Messages with control characters (non-printable bytes) may cause parsing issues in rsyslog, syslog-ng, or AMA.",
                Recommendation = "Check source encoding. Ensure messages are UTF-8 encoded without binary content.",
                RelatedMessageIndices = withControlChars.Take(10).Select(m => m.Index).ToList()
            });
        }

        // Empty or very short messages
        var tooShort = messages.Where(m => m.RawMessage.Length < 10 && m.DetectedFormat != SyslogFormat.Invalid).ToList();
        if (tooShort.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{tooShort.Count} messages are suspiciously short (< 10 bytes)",
                Detail = "Very short messages may be keepalives, empty lines, or truncated messages.",
                RelatedMessageIndices = tooShort.Take(10).Select(m => m.Index).ToList()
            });
        }

        return findings;
    }
}
