namespace SyslogCEFAnalyzer.Parsers;

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SyslogCEFAnalyzer.Models;

/// <summary>
/// Parses individual syslog lines into structured SyslogMessage objects.
/// Supports RFC 3164 (BSD), RFC 5424 (IETF), and CEF format detection.
/// </summary>
public static partial class SyslogParser
{
    // RFC 3164: <PRI>Mmm dd HH:mm:ss HOSTNAME TAG: MSG
    // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // CEF:      <PRI>...CEF:0|vendor|product|version|classId|name|severity|extension

    private static readonly string[] Rfc3164Months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

    /// <summary>Parse a single syslog line into a SyslogMessage.</summary>
    public static SyslogMessage ParseLine(string line, int index, InputSource source)
    {
        var msg = new SyslogMessage { Index = index, RawMessage = line, Source = source };

        if (string.IsNullOrWhiteSpace(line))
        {
            msg.DetectedFormat = SyslogFormat.Invalid;
            msg.ValidationErrors.Add("Empty message");
            return msg;
        }

        int offset = 0;

        // ── Parse PRI ────────────────────────────────────────────
        if (line.StartsWith('<'))
        {
            int closeAngle = line.IndexOf('>', 1);
            if (closeAngle > 1 && closeAngle <= 4) // <0> to <191>
            {
                if (int.TryParse(line.AsSpan(1, closeAngle - 1), out int pri) && pri >= 0 && pri <= 191)
                {
                    msg.PriValue = pri;
                    msg.Facility = (SyslogFacility)(pri / 8);
                    msg.SyslogSeverity = (SyslogSeverity)(pri % 8);
                    offset = closeAngle + 1;
                }
                else
                {
                    msg.ValidationErrors.Add($"Invalid PRI value: {line[1..closeAngle]} (must be 0-191)");
                    msg.DetectedFormat = SyslogFormat.Invalid;
                    msg.Message = line;
                    return msg;
                }
            }
            else if (closeAngle > 4) // PRI too long like <999>
            {
                if (int.TryParse(line.AsSpan(1, closeAngle - 1), out int bigPri))
                    msg.ValidationErrors.Add($"PRI value {bigPri} exceeds maximum of 191");
                else
                    msg.ValidationErrors.Add($"Non-numeric PRI value: {line[1..closeAngle]}");
                msg.DetectedFormat = SyslogFormat.Invalid;
                msg.Message = line;
                return msg;
            }
            else
            {
                msg.ValidationErrors.Add("Malformed PRI field — missing or invalid angle brackets");
                msg.DetectedFormat = SyslogFormat.Invalid;
                msg.Message = line;
                return msg;
            }
        }

        string afterPri = line[offset..];

        // ── Detect CEF anywhere in the message ───────────────────
        int cefIdx = afterPri.IndexOf("CEF:", StringComparison.Ordinal);
        if (cefIdx >= 0)
        {
            msg.DetectedFormat = SyslogFormat.CEF;
            // Parse the syslog header before CEF if present
            if (cefIdx > 0)
                ParseSyslogHeaderBeforeCef(afterPri[..cefIdx].Trim(), msg);
            ParseCef(afterPri[cefIdx..], msg);
            return msg;
        }

        // ── Detect RFC 5424 (starts with version number after PRI) ─
        if (afterPri.Length > 0 && afterPri[0] >= '1' && afterPri[0] <= '9')
        {
            int sp = afterPri.IndexOf(' ');
            if (sp > 0 && sp <= 2 && int.TryParse(afterPri[..sp], out int ver))
            {
                msg.DetectedFormat = SyslogFormat.RFC5424;
                msg.Rfc5424Version = ver;
                ParseRfc5424(afterPri[(sp + 1)..], msg);
                return msg;
            }
        }

        // ── Default: RFC 3164 or Invalid ────────────────────────
        // Only classify as RFC 3164 if we have a valid PRI or the line starts with a recognizable timestamp
        if (msg.PriValue.HasValue)
        {
            msg.DetectedFormat = SyslogFormat.RFC3164;
            ParseRfc3164(afterPri, msg);
        }
        else if (afterPri.Length >= 3 && Rfc3164Months.Contains(afterPri[..3], StringComparer.Ordinal))
        {
            // No PRI but has a valid month — treat as RFC 3164 with warning
            msg.DetectedFormat = SyslogFormat.RFC3164;
            msg.ValidationWarnings.Add("Missing PRI field (<facility.severity>) before timestamp");
            ParseRfc3164(afterPri, msg);
        }
        else
        {
            // No PRI, no recognizable format — mark as Invalid
            msg.DetectedFormat = SyslogFormat.Invalid;
            msg.Message = line;
            msg.ValidationErrors.Add("No valid syslog header detected — missing PRI field and no recognizable RFC 3164/5424/CEF format");
        }
        return msg;
    }

    // ── RFC 3164 parsing ─────────────────────────────────────────────

    private static void ParseRfc3164(string text, SyslogMessage msg)
    {
        // Expected: Mmm dd HH:mm:ss HOSTNAME TAG: MSG
        // Timestamp: "Jan  1 00:00:00" or "Jan 01 00:00:00" (15 or 16 chars)

        if (text.Length < 15)
        {
            msg.Message = text;
            msg.ValidationWarnings.Add("Message too short for RFC 3164 timestamp");
            return;
        }

        // Try to parse the timestamp
        string monthStr = text[..3];
        bool validMonth = Rfc3164Months.Contains(monthStr, StringComparer.Ordinal);

        if (validMonth && text.Length >= 15)
        {
            // Find end of timestamp (Mmm dd HH:mm:ss or Mmm  d HH:mm:ss)
            int tsEnd = 15;
            if (text.Length > 15 && text[15] != ' ')
                tsEnd = Math.Min(16, text.Length);

            msg.Rfc3164Timestamp = text[..tsEnd].Trim();

            // Validate timestamp format
            if (!ValidateRfc3164Timestamp(msg.Rfc3164Timestamp))
                msg.ValidationWarnings.Add($"Timestamp may not be in standard RFC 3164 format: '{msg.Rfc3164Timestamp}'");

            string rest = text[tsEnd..].TrimStart();

            // Next token is hostname
            int spIdx = rest.IndexOf(' ');
            if (spIdx > 0)
            {
                msg.Hostname = rest[..spIdx];
                string afterHost = rest[(spIdx + 1)..];

                // Tag is everything up to ": " or ":" or first space
                int colonIdx = afterHost.IndexOf(':');
                if (colonIdx > 0)
                {
                    string tagPart = afterHost[..colonIdx];
                    // Extract PID if present: tag[pid]
                    int bracketIdx = tagPart.IndexOf('[');
                    if (bracketIdx > 0)
                    {
                        msg.Tag = tagPart[..bracketIdx];
                        msg.AppName = msg.Tag;
                        int closeBracket = tagPart.IndexOf(']', bracketIdx);
                        if (closeBracket > bracketIdx)
                            msg.ProcId = tagPart[(bracketIdx + 1)..closeBracket];
                    }
                    else
                    {
                        msg.Tag = tagPart;
                        msg.AppName = tagPart;
                    }
                    msg.Message = afterHost[(colonIdx + 1)..].TrimStart();
                }
                else
                {
                    msg.Message = afterHost;
                }
            }
            else
            {
                msg.Hostname = rest;
            }
        }
        else
        {
            msg.Message = text;
            if (!validMonth)
                msg.ValidationWarnings.Add($"Does not start with a valid RFC 3164 month abbreviation (got '{monthStr}')");
        }
    }

    private static bool ValidateRfc3164Timestamp(string ts)
    {
        // Expected: "Mmm dd HH:mm:ss" or "Mmm  d HH:mm:ss"
        if (ts.Length < 14) return false;
        string month = ts[..3];
        if (!Rfc3164Months.Contains(month)) return false;
        // Rough check for dd HH:mm:ss pattern
        return ts.Length >= 14 && ts[^8] == ':' && ts[^5] == ':';
    }

    // ── RFC 5424 parsing ─────────────────────────────────────────────

    private static void ParseRfc5424(string text, SyslogMessage msg)
    {
        // Expected: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [BOM]MSG
        // Each field separated by space, NILVALUE is "-"

        var fields = new List<string>();
        int pos = 0;

        // Parse 5 space-delimited fields: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        for (int i = 0; i < 5 && pos < text.Length; i++)
        {
            int sp = text.IndexOf(' ', pos);
            if (sp < 0) { fields.Add(text[pos..]); pos = text.Length; break; }
            fields.Add(text[pos..sp]);
            pos = sp + 1;
        }

        if (fields.Count >= 1)
        {
            msg.Rfc5424Timestamp = fields[0] == "-" ? null : fields[0];
            if (msg.Rfc5424Timestamp != null && !ValidateRfc5424Timestamp(msg.Rfc5424Timestamp))
                msg.ValidationWarnings.Add($"Timestamp is not valid ISO 8601: '{msg.Rfc5424Timestamp}'");
        }
        if (fields.Count >= 2) msg.Hostname = fields[1] == "-" ? null : fields[1];
        if (fields.Count >= 3) msg.AppName = fields[2] == "-" ? null : fields[2];
        if (fields.Count >= 4) msg.ProcId = fields[3] == "-" ? null : fields[3];
        if (fields.Count >= 5) msg.MsgId = fields[4] == "-" ? null : fields[4];

        // Parse structured data
        if (pos < text.Length)
        {
            if (text[pos] == '[')
            {
                // Find matching close bracket(s) with depth limit
                int sdEnd = pos;
                int depth = 0;
                const int MaxSdDepth = 100;
                while (sdEnd < text.Length && depth < MaxSdDepth)
                {
                    if (text[sdEnd] == '[') depth++;
                    else if (text[sdEnd] == ']') { depth--; if (depth == 0) { sdEnd++; break; } }
                    sdEnd++;
                }
                if (depth >= MaxSdDepth)
                    msg.ValidationWarnings.Add("Structured data nesting exceeds maximum depth");
                // There could be multiple SD elements
                while (sdEnd < text.Length && text[sdEnd] == '[')
                {
                    while (sdEnd < text.Length && text[sdEnd] != ']') sdEnd++;
                    if (sdEnd < text.Length && text[sdEnd] == ']') sdEnd++;
                }
                msg.StructuredData = text[pos..sdEnd];
                pos = sdEnd;
            }
            else if (text[pos] == '-')
            {
                msg.StructuredData = null; // NILVALUE
                pos++;
            }

            // Skip space before MSG
            if (pos < text.Length && text[pos] == ' ') pos++;

            // Skip BOM if present (UTF-8 BOM: EF BB BF)
            if (pos + 3 <= text.Length && text[pos] == '\xEF' && text[pos + 1] == '\xBB' && text[pos + 2] == '\xBF')
                pos += 3;

            msg.Message = pos < text.Length ? text[pos..] : null;
        }

        // Validate field lengths per RFC 5424
        if (msg.Hostname?.Length > 255)
            msg.ValidationErrors.Add($"HOSTNAME exceeds 255 chars ({msg.Hostname.Length})");
        if (msg.AppName?.Length > 48)
            msg.ValidationErrors.Add($"APP-NAME exceeds 48 chars ({msg.AppName.Length})");
        if (msg.ProcId?.Length > 128)
            msg.ValidationErrors.Add($"PROCID exceeds 128 chars ({msg.ProcId.Length})");
        if (msg.MsgId?.Length > 32)
            msg.ValidationErrors.Add($"MSGID exceeds 32 chars ({msg.MsgId.Length})");
    }

    private static bool ValidateRfc5424Timestamp(string ts)
    {
        if (ts == "-") return true;
        // ISO 8601: YYYY-MM-DDTHH:MM:SS[.frac]Z or with timezone offset
        return ts.Length >= 19 && ts[4] == '-' && ts[7] == '-' && ts[10] == 'T';
    }

    // ── CEF parsing ──────────────────────────────────────────────────

    private static void ParseCef(string text, SyslogMessage msg)
    {
        // CEF:version|vendor|product|deviceVersion|deviceEventClassId|name|severity|extension
        var cef = new CefHeader();
        msg.Cef = cef;

        if (!text.StartsWith("CEF:"))
        {
            msg.ValidationErrors.Add("CEF message does not start with 'CEF:'");
            return;
        }

        string cefContent = text[4..]; // Skip "CEF:"

        // Split on unescaped pipes — CEF uses \| for escaped pipes
        var parts = SplitCefPipes(cefContent);
        cef.PipeCount = parts.Count > 0 ? parts.Count - 1 : 0;

        if (parts.Count >= 1)
        {
            if (int.TryParse(parts[0], out int ver))
                cef.CefVersion = ver;
            else
                msg.ValidationErrors.Add($"CEF version is not a number: '{parts[0]}'");
        }
        if (parts.Count >= 2) cef.DeviceVendor = parts[1];
        if (parts.Count >= 3) cef.DeviceProduct = parts[2];
        if (parts.Count >= 4) cef.DeviceVersion = parts[3];
        if (parts.Count >= 5) cef.DeviceEventClassId = parts[4];
        if (parts.Count >= 6) cef.Name = parts[5];
        if (parts.Count >= 7) cef.Severity = parts[6];
        if (parts.Count >= 8)
        {
            string ext = string.Join("|", parts.Skip(7));
            const int MaxExtensionSize = 8192;
            if (ext.Length > MaxExtensionSize)
            {
                cef.Extension = ext[..MaxExtensionSize];
                msg.ValidationWarnings.Add($"CEF extension field truncated from {ext.Length} to {MaxExtensionSize} bytes for analysis");
            }
            else
            {
                cef.Extension = ext;
            }
        }

        if (parts.Count < 7)
            msg.ValidationErrors.Add($"CEF header has {cef.PipeCount} pipes (expected exactly 7 separating 8 fields). Missing fields.");
    }

    private static List<string> SplitCefPipes(string text)
    {
        var parts = new List<string>();
        var current = new StringBuilder();

        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '\\' && i + 1 < text.Length && text[i + 1] == '|')
            {
                current.Append('|');
                i++; // skip escaped pipe
            }
            else if (text[i] == '|')
            {
                parts.Add(current.ToString());
                current.Clear();
                // After 7th pipe, rest is extension (may contain unescaped pipes in values)
                if (parts.Count == 7)
                {
                    parts.Add(text[(i + 1)..]);
                    return parts;
                }
            }
            else
            {
                current.Append(text[i]);
            }
        }
        parts.Add(current.ToString());
        return parts;
    }

    // ── Helper: parse syslog header before CEF payload ───────────────

    private static void ParseSyslogHeaderBeforeCef(string header, SyslogMessage msg)
    {
        // The syslog header before CEF could be RFC 3164 or RFC 5424 format
        // Try to extract hostname and timestamp
        if (header.Length < 5) return;

        // Check for RFC 3164 timestamp pattern
        string month = header.Length >= 3 ? header[..3] : "";
        if (Rfc3164Months.Contains(month))
        {
            // Rough parse: "Mmm dd HH:mm:ss hostname"
            int tsEnd = Math.Min(header.Length, 15);
            msg.Rfc3164Timestamp = header[..tsEnd].Trim();

            string rest = header[tsEnd..].TrimStart();
            int sp = rest.IndexOf(' ');
            msg.Hostname = sp > 0 ? rest[..sp] : rest;
        }
    }

    /// <summary>Parse a log file (syslog/messages) line by line.</summary>
    public static List<SyslogMessage> ParseLogFile(string filePath)
    {
        const int MaxLineLength = 65536; // 64 KB per line
        var messages = new List<SyslogMessage>();
        int index = 0;

        foreach (string line in File.ReadLines(filePath, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            string safeLine = line.Length > MaxLineLength ? line[..MaxLineLength] : line;
            var msg = ParseLine(safeLine, index++, InputSource.LogFile);
            if (line.Length > MaxLineLength)
                msg.ValidationWarnings.Add($"Line truncated from {line.Length} to {MaxLineLength} bytes");
            messages.Add(msg);
        }

        return messages;
    }
}
