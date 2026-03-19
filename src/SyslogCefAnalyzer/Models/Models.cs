namespace SyslogCEFAnalyzer.Models;

// ── Link-layer types for pcap parsing ────────────────────────────────
public enum LinkLayerType : uint
{
    Ethernet = 1,
    Raw = 101,
    LinuxSll = 113
}

// ── Raw packet from pcap file ────────────────────────────────────────
public sealed record RawPacket(DateTime Timestamp, byte[] Data, LinkLayerType LinkType);

// ── Input source type ────────────────────────────────────────────────
public enum InputSource { PcapFile, LogFile }

// ── Syslog RFC format ────────────────────────────────────────────────
public enum SyslogFormat { Unknown, RFC3164, RFC5424, CEF, Invalid }

// ── Syslog facility codes (RFC 5424 §6.2.1) ─────────────────────────
public enum SyslogFacility
{
    Kern = 0, User = 1, Mail = 2, Daemon = 3, Auth = 4, Syslog = 5,
    Lpr = 6, News = 7, Uucp = 8, Cron = 9, AuthPriv = 10, Ftp = 11,
    Ntp = 12, Audit = 13, Alert = 14, Clock = 15,
    Local0 = 16, Local1 = 17, Local2 = 18, Local3 = 19,
    Local4 = 20, Local5 = 21, Local6 = 22, Local7 = 23
}

// ── Syslog severity codes (RFC 5424 §6.2.1) ─────────────────────────
public enum SyslogSeverity
{
    Emergency = 0, Alert = 1, Critical = 2, Error = 3,
    Warning = 4, Notice = 5, Informational = 6, Debug = 7
}

// ── Finding severity ─────────────────────────────────────────────────
public enum Severity { Pass, Info, Warning, Error }

// ── A single syslog/CEF message (parsed or raw) ─────────────────────
public sealed class SyslogMessage
{
    public int Index { get; init; }
    public string RawMessage { get; init; } = "";
    public InputSource Source { get; init; }

    // From pcap only
    public DateTime? PacketTimestamp { get; set; }
    public string? SourceIp { get; set; }
    public string? DestIp { get; set; }
    public ushort SourcePort { get; set; }
    public ushort DestPort { get; set; }
    public string? Protocol { get; set; } // "TCP", "UDP", "TLS"

    // Parsed PRI
    public int? PriValue { get; set; }
    public SyslogFacility? Facility { get; set; }
    public SyslogSeverity? SyslogSeverity { get; set; }

    // Format detection
    public SyslogFormat DetectedFormat { get; set; } = SyslogFormat.Unknown;

    // RFC 3164 fields
    public string? Rfc3164Timestamp { get; set; }  // Mmm dd HH:mm:ss
    public string? Hostname { get; set; }
    public string? Tag { get; set; }               // APP-NAME[PID]:
    public string? Message { get; set; }

    // RFC 5424 fields
    public int? Rfc5424Version { get; set; }
    public string? Rfc5424Timestamp { get; set; }  // ISO 8601
    public string? AppName { get; set; }
    public string? ProcId { get; set; }
    public string? MsgId { get; set; }
    public string? StructuredData { get; set; }

    // CEF fields
    public CefHeader? Cef { get; set; }

    // Validation issues found on this message
    public List<string> ValidationErrors { get; set; } = [];
    public List<string> ValidationWarnings { get; set; } = [];

    public bool IsValid => ValidationErrors.Count == 0;
}

// ── CEF header fields ────────────────────────────────────────────────
public sealed class CefHeader
{
    public int? CefVersion { get; set; }       // 0 or 1
    public string? DeviceVendor { get; set; }
    public string? DeviceProduct { get; set; }
    public string? DeviceVersion { get; set; }
    public string? DeviceEventClassId { get; set; }
    public string? Name { get; set; }
    public string? Severity { get; set; }      // 0-10 or string like "Low"
    public string? Extension { get; set; }     // key=value pairs
    public int PipeCount { get; set; }         // Should be exactly 7 pipes
}

// ── Analysis finding ─────────────────────────────────────────────────
public sealed class AnalysisFinding
{
    public required string RuleName { get; init; }
    public required string Category { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public string? Recommendation { get; init; }
    public string? WiresharkFilter { get; init; }
    public List<int> RelatedMessageIndices { get; init; } = [];
}

// ── Analysis report ──────────────────────────────────────────────────
public sealed class AnalysisReport
{
    public string FileName { get; set; } = "";
    public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;
    public InputSource Source { get; set; }
    public int TotalMessages { get; set; }
    public int Rfc3164Count { get; set; }
    public int Rfc5424Count { get; set; }
    public int CefCount { get; set; }
    public int InvalidCount { get; set; }
    public List<AnalysisFinding> Findings { get; set; } = [];

    public int PassCount => Findings.Count(f => f.Severity == Severity.Pass);
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);
    public int ErrorCount => Findings.Count(f => f.Severity == Severity.Error);
}

// ── AMA-supported syslog ports ───────────────────────────────────────
public static class SyslogPorts
{
    public const ushort SyslogUdp = 514;
    public const ushort SyslogTcp = 514;
    public const ushort SyslogTls = 6514;
    public const ushort AmaListener = 28330;

    public static bool IsSyslogPort(ushort port) =>
        port is SyslogUdp or SyslogTcp or SyslogTls or AmaListener;
}
