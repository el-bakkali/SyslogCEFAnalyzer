namespace SyslogCEFAnalyzer.Analysis.Rules;

using SyslogCEFAnalyzer.Models;

/// <summary>
/// Rule 2 — Validates PRI field (facility/severity) on all messages.
/// AMA requires valid PRI values 0-191.
/// </summary>
public sealed class PriValidationRule : IAnalysisRule
{
    public string Name => "PRI Validation";
    public string Category => "PRI Field";

    public List<AnalysisFinding> Analyze(List<SyslogMessage> messages)
    {
        var findings = new List<AnalysisFinding>();

        var withPri = messages.Where(m => m.PriValue.HasValue).ToList();
        var withoutPri = messages.Where(m => !m.PriValue.HasValue && m.DetectedFormat != SyslogFormat.Invalid).ToList();

        if (withoutPri.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Warning,
                Title = $"{withoutPri.Count} messages missing PRI field",
                Detail = $"Messages without a <PRI> header: {withoutPri.Count}. The PRI field is required by both RFC 3164 and RFC 5424. Messages without PRI may be dropped by rsyslog/syslog-ng or misclassified by AMA.",
                Recommendation = "Ensure the source device includes a valid <PRI> value (e.g., <134> for local0.informational). Check the device's syslog configuration.",
                ComplianceTag = "NIST-DE.AE-3 | CIS-8.2 | ISO-27034-A.12",
                RelatedMessageIndices = withoutPri.Take(20).Select(m => m.Index).ToList()
            });
        }

        if (withPri.Count > 0)
        {
            // Check facility distribution
            var facilityGroups = withPri.GroupBy(m => m.Facility).OrderByDescending(g => g.Count()).ToList();
            var severityGroups = withPri.GroupBy(m => m.SyslogSeverity).OrderByDescending(g => g.Count()).ToList();

            string facilityDetail = string.Join("\n", facilityGroups.Select(g => $"  {g.Key} ({(int)g.Key!.Value}): {g.Count()} messages"));
            string severityDetail = string.Join("\n", severityGroups.Select(g => $"  {g.Key} ({(int)g.Key!.Value}): {g.Count()} messages"));

            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Info,
                Title = $"Facility/Severity distribution across {withPri.Count} messages",
                Detail = $"Facilities:\n{facilityDetail}\n\nSeverities:\n{severityDetail}",
                Recommendation = "Verify the facility matches your AMA Data Collection Rule (DCR). Common: Local0-Local7 for custom applications, Auth/AuthPriv for security logs."
            });

            // Check if all messages use the same facility (common misconfiguration)
            if (facilityGroups.Count == 1 && withPri.Count > 10)
            {
                findings.Add(new AnalysisFinding
                {
                    RuleName = Name, Category = Category, Severity = Severity.Info,
                    Title = $"All messages use facility {facilityGroups[0].Key}",
                    Detail = $"Every message uses facility {facilityGroups[0].Key} ({(int)facilityGroups[0].Key!.Value}). This is normal for single-source devices but may indicate the source isn't differentiating log types.",
                });
            }
        }

        if (withPri.Count > 0 && withoutPri.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                RuleName = Name, Category = Category, Severity = Severity.Pass,
                Title = "All messages have valid PRI fields",
                Detail = $"{withPri.Count} messages with valid PRI values (facility + severity)."
            });
        }

        return findings;
    }
}
