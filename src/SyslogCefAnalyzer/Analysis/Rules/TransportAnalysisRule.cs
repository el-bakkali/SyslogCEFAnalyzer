namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 7 — Transport analysis (pcap only): port usage, protocol mix, source IPs.
/// Validates that syslog traffic is reaching the expected ports.
/// </summary>
public sealed class TransportAnalysisRule : IAnalysisRule
{
    public string Name => "Transport Analysis";
    public string Category => "Transport / Network";

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();
        var pcapMessages = messages.Where(m => m.Source == InputSource.PcapFile).ToList();

        if (pcapMessages.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "Transport analysis skipped (log file input)",
                Detail = "Transport/network analysis is only available for pcap/pcapng inputs."
            });
            return findings;
        }

        // Protocol distribution
        var protoGroups = pcapMessages.GroupBy(m => m.Protocol).ToList();
        string protoSummary = string.Join(", ", protoGroups.Select(g => $"{g.Key}: {g.Count()}"));
        findings.Add(new AnalysisFinding
        {
            RuleName = Name, Category = Category, Severity = Severity.Info,
            Title = $"Protocols: {protoSummary}",
            Detail = $"Syslog messages by protocol:\n{string.Join("\n", protoGroups.Select(g => $"  {g.Key}: {g.Count()} messages"))}"
        });

        // Port analysis
        var destPortGroups = pcapMessages.GroupBy(m => m.DestPort).OrderByDescending(g => g.Count()).ToList();
        string portSummary = string.Join("\n", destPortGroups.Select(g =>
        {
            string portName = g.Key switch
            {
                514 => "514 (standard syslog)",
                6514 => "6514 (syslog over TLS)",
                28330 => "28330 (AMA listener)",
                _ => $"{g.Key} (non-standard)"
            };
            return $"  Port {portName}: {g.Count()} messages";
        }));

        findings.Add(new AnalysisFinding
        {
            RuleName = Name, Category = Category, Severity = Severity.Info,
            Title = $"Destination ports: {string.Join(", ", destPortGroups.Select(g => g.Key))}",
            Detail = portSummary
        });

        // Non-standard ports
        var nonStandard = destPortGroups.Where(g => !SyslogPorts.IsSyslogPort(g.Key)).ToList();
        if (nonStandard.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"Traffic on non-standard syslog ports: {string.Join(", ", nonStandard.Select(g => g.Key))}",
                Detail = "Standard syslog ports are 514 (TCP/UDP), 6514 (TLS), and 28330 (AMA). Traffic on other ports may not reach the syslog daemon or AMA.",
                Recommendation = "Verify the source device is configured to send to port 514 (or 6514 for TLS). AMA listens on port 28330 internally.",
                WiresharkFilter = string.Join(" || ", nonStandard.Select(g => $"tcp.port == {g.Key} || udp.port == {g.Key}"))
            });
        }

        // Source IP summary
        var srcIpGroups = pcapMessages
            .Where(m => m.SourceIp is not null)
            .GroupBy(m => m.SourceIp!)
            .OrderByDescending(g => g.Count())
            .ToList();

        if (srcIpGroups.Count > 0)
        {
            string ipSummary = string.Join("\n", srcIpGroups.Take(10).Select(g => $"  {g.Key}: {g.Count()} messages"));
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"Source IPs: {srcIpGroups.Count} unique sources",
                Detail = $"Top sources:\n{ipSummary}"
            });
        }

        // UDP vs TCP recommendation
        bool hasUdp = protoGroups.Any(g => g.Key == "UDP");
        bool hasTcp = protoGroups.Any(g => g.Key == "TCP");

        if (hasUdp && !hasTcp)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "All traffic is UDP — consider TCP for reliability",
                Detail = "UDP syslog can lose messages under network congestion or high volume. TCP provides reliable delivery with acknowledgment.",
                Recommendation = "For production workloads, consider switching to TCP port 514 or TLS port 6514."
            });
        }

        return findings;
    }
}
