namespace SyslogCEFAnalyzer.Analysis.Rules;

using System.Text.RegularExpressions;
using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 8 — Detects and validates Cisco ASA and FTD syslog message formats.
/// These are extremely common CEF sources for Microsoft Sentinel.
/// ASA format: %ASA-severity-messageId: message text
/// FTD format: %FTD-severity-messageId: message text
/// Also detects Cisco messages wrapped in CEF format.
/// </summary>
public sealed partial class CiscoAsaFtdRule : IAnalysisRule
{
    public string Name => "Cisco ASA/FTD Detection";
    public string Category => "Cisco ASA / FTD";

    // %ASA-4-106023: Deny tcp src outside:203.0.113.5/12345 dst inside:10.0.0.100/443
    // %FTD-6-305012: Teardown dynamic TCP translation from inside:10.0.0.1/54321 to outside:198.51.100.1/54321
    [GeneratedRegex(@"%(ASA|FTD)-(\d)-(\d{6}):\s*(.{0,1024})", RegexOptions.Compiled)]
    private static partial Regex CiscoMessagePattern();

    // Cisco ASA in CEF: CEF:0|Cisco|ASA|...
    private static readonly string[] CiscoCefProducts = ["ASA", "Adaptive Security Appliance", "FTD", "Firepower", "FTDV"];

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();

        // ── Detect native Cisco syslog format (%ASA-x-xxxxxx / %FTD-x-xxxxxx) ──
        var nativeCiscoMessages = new List<(SyslogMessage Msg, string Platform, int Severity, string MessageId, string Text)>();

        foreach (var msg in messages)
        {
            string content = msg.Message ?? msg.RawMessage;
            var match = CiscoMessagePattern().Match(content);
            if (match.Success)
            {
                string platform = match.Groups[1].Value; // ASA or FTD
                int severity = int.Parse(match.Groups[2].Value);
                string messageId = match.Groups[3].Value;
                string text = match.Groups[4].Value;
                nativeCiscoMessages.Add((msg, platform, severity, messageId, text));
            }
        }

        // ── Detect Cisco CEF messages ──
        var ciscoCefMessages = messages
            .Where(m => m.Cef is not null &&
                        CiscoCefProducts.Any(p =>
                            (m.Cef.DeviceVendor?.Contains("Cisco", StringComparison.OrdinalIgnoreCase) == true &&
                             m.Cef.DeviceProduct != null &&
                             CiscoCefProducts.Any(cp => m.Cef.DeviceProduct.Contains(cp, StringComparison.OrdinalIgnoreCase))) ||
                            (m.Cef.DeviceProduct?.Contains(p, StringComparison.OrdinalIgnoreCase) == true)))
            .ToList();

        int totalCisco = nativeCiscoMessages.Count + ciscoCefMessages.Count;

        if (totalCisco == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "No Cisco ASA/FTD messages detected",
                Detail = "No Cisco ASA or FTD formatted messages found. This rule checks for native Cisco syslog format (%ASA-x-xxxxxx, %FTD-x-xxxxxx) and Cisco CEF messages."
            });
            return findings;
        }

        // ── Native format analysis ──
        if (nativeCiscoMessages.Count > 0)
        {
            var asaMessages = nativeCiscoMessages.Where(m => m.Platform == "ASA").ToList();
            var ftdMessages = nativeCiscoMessages.Where(m => m.Platform == "FTD").ToList();

            // Platform summary
            var platformSummary = new List<string>();
            if (asaMessages.Count > 0) platformSummary.Add($"ASA: {asaMessages.Count}");
            if (ftdMessages.Count > 0) platformSummary.Add($"FTD: {ftdMessages.Count}");

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = $"Cisco native syslog detected: {string.Join(", ", platformSummary)}",
                Detail = $"Found {nativeCiscoMessages.Count} messages in native Cisco format (%ASA/FTD-severity-messageId).",
                RelatedMessageIndices = nativeCiscoMessages.Take(10).Select(m => m.Msg.Index).ToList()
            });

            // Severity distribution
            var severityGroups = nativeCiscoMessages
                .GroupBy(m => m.Severity)
                .OrderBy(g => g.Key)
                .ToList();

            string sevDetail = string.Join("\n", severityGroups.Select(g =>
            {
                string sevName = g.Key switch
                {
                    0 => "Emergency", 1 => "Alert", 2 => "Critical", 3 => "Error",
                    4 => "Warning", 5 => "Notification", 6 => "Informational", 7 => "Debug",
                    _ => $"Unknown({g.Key})"
                };
                return $"  Level {g.Key} ({sevName}): {g.Count()} messages";
            }));

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"Cisco severity distribution across {nativeCiscoMessages.Count} messages",
                Detail = sevDetail
            });

            // Top message IDs
            var topMessageIds = nativeCiscoMessages
                .GroupBy(m => $"{m.Platform}-{m.MessageId}")
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToList();

            string msgIdDetail = string.Join("\n", topMessageIds.Select(g =>
                $"  %{g.Key}: {g.Count()} messages — {g.First().Text.Truncate(80)}"));

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"Top {topMessageIds.Count} Cisco message IDs",
                Detail = msgIdDetail
            });

            // Check for common important message IDs
            CheckImportantMessageIds(nativeCiscoMessages, findings);

            // Validate PRI is present (Cisco devices sometimes omit it)
            var noPri = nativeCiscoMessages.Where(m => !m.Msg.PriValue.HasValue).ToList();
            if (noPri.Count > 0)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name, Category = Category, Severity = Severity.Warning,
                    Title = $"{noPri.Count} Cisco messages missing PRI field",
                    Detail = "Cisco ASA/FTD messages without a syslog PRI header may not be correctly routed by rsyslog/syslog-ng to AMA.",
                    Recommendation = "Configure the Cisco device to send syslog messages with a PRI header. In ASA: 'logging facility 23' sets local7.",
                    RelatedMessageIndices = noPri.Take(10).Select(m => m.Msg.Index).ToList()
                });
            }
        }

        // ── CEF format analysis ──
        if (ciscoCefMessages.Count > 0)
        {
            var cefProducts = ciscoCefMessages
                .GroupBy(m => $"{m.Cef!.DeviceVendor}/{m.Cef.DeviceProduct}")
                .Select(g => $"  {g.Key}: {g.Count()} messages")
                .ToList();

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = $"Cisco CEF messages detected: {ciscoCefMessages.Count}",
                Detail = $"Cisco devices sending in CEF format:\n{string.Join("\n", cefProducts)}",
                Recommendation = "Cisco CEF messages will be ingested into the CommonSecurityLog table in Microsoft Sentinel. Ensure your DCR uses the SECURITY_CEF_BLOB or SECURITY_CISCO_ASA_BLOB stream.",
                RelatedMessageIndices = ciscoCefMessages.Take(10).Select(m => m.Index).ToList()
            });
        }

        // ── DCR stream recommendation ──
        if (nativeCiscoMessages.Any(m => m.Platform == "ASA") || ciscoCefMessages.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = "Sentinel DCR stream recommendation",
                Detail = "For Cisco ASA/FTD messages routed through CEF, use the SECURITY_CISCO_ASA_BLOB stream in your Data Collection Rule. For native syslog format, use LINUX_SYSLOGS_BLOB.",
                Recommendation = "In Microsoft Sentinel, create a DCR with the appropriate stream. CEF → CommonSecurityLog table. Native syslog → Syslog table."
            });
        }

        return findings;
    }

    private static void CheckImportantMessageIds(
        List<(SyslogMessage Msg, string Platform, int Severity, string MessageId, string Text)> messages,
        List<AnalysisFinding> findings)
    {
        // Common security-relevant ASA message IDs
        var securityIds = new Dictionary<string, string>
        {
            ["106001"] = "Inbound TCP connection denied",
            ["106006"] = "Deny inbound UDP",
            ["106007"] = "Deny inbound UDP (no connection)",
            ["106014"] = "Deny inbound icmp",
            ["106015"] = "Deny inbound TCP (no connection)",
            ["106023"] = "Deny by access-group",
            ["106100"] = "Access list hit (permit/deny)",
            ["302013"] = "Built inbound TCP connection",
            ["302014"] = "Teardown TCP connection",
            ["302015"] = "Built inbound UDP connection",
            ["302016"] = "Teardown UDP connection",
            ["305011"] = "Built dynamic TCP translation",
            ["305012"] = "Teardown dynamic translation",
            ["313001"] = "Denied ICMP type",
            ["402117"] = "IPSEC: SPI mismatch",
            ["402119"] = "IPSEC: decrypt failure",
            ["710003"] = "TCP access denied by ACL",
            ["733100"] = "Threat detection rate exceeded",
        };

        var foundSecurityEvents = messages
            .Where(m => securityIds.ContainsKey(m.MessageId))
            .GroupBy(m => m.MessageId)
            .OrderByDescending(g => g.Count())
            .ToList();

        if (foundSecurityEvents.Count > 0)
        {
            string detail = string.Join("\n", foundSecurityEvents.Select(g =>
                $"  %ASA/{g.First().Platform}-{g.Key} ({securityIds[g.Key]}): {g.Count()} events"));

            findings.Add(new AnalysisFinding
            {
                RuleName = "Cisco ASA/FTD Detection",
                Category = "Cisco ASA / FTD",
                Severity = Severity.Info,
                Title = $"Security-relevant Cisco events: {foundSecurityEvents.Sum(g => g.Count())} events across {foundSecurityEvents.Count} message types",
                Detail = detail
            });
        }
    }
}

// Helper extension — available project-wide
internal static class StringExtensions
{
    public static string Truncate(this string? value, int maxLength)
    {
        if (value is null) return "";
        return value.Length <= maxLength ? value : value[..maxLength] + "…";
    }
}
