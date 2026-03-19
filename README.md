# Syslog / CEF Analyzer

A Windows desktop tool for novice engineers to validate syslog and CEF message formats before they reach Azure Monitor Agent (AMA) and Microsoft Sentinel.

**Drop a `.pcap`, `.pcapng`, or log file → instantly see which messages are valid, malformed, or missing required fields.**

## The Problem This Solves

When syslog/CEF messages aren't arriving in Log Analytics or Sentinel, engineers waste hours guessing whether the issue is at the source device, the forwarder, or the agent. This tool analyzes the messages themselves and tells you exactly what's wrong — before they ever reach AMA.

## Features

- **Drag-and-drop** pcap captures or log files
- **Two input modes:**
  - **Pcap/pcapng** — extracts syslog payloads from ports 514, 6514 (TLS), and 28330 (AMA)
  - **Log files** — parses `/var/log/syslog`, `/var/log/messages`, or any text file line by line
- **8 automated diagnostic rules:**
  1. **Format Detection** — Identifies RFC 3164, RFC 5424, CEF, and invalid messages with breakdown
  2. **PRI Validation** — Checks facility/severity values (0-191), distribution across messages
  3. **RFC 3164 Validation** — Timestamp (`Mmm dd HH:mm:ss`), hostname, tag, message body
  4. **RFC 5424 Validation** — Version, ISO 8601 timestamp, hostname, app-name, field length limits
  5. **CEF Validation** — Pipe count (exactly 7), version, vendor/product, severity values, extensions
  6. **Cisco ASA/FTD Detection** — Native `%ASA`/`%FTD` format and Cisco CEF, severity distribution, top message IDs, security event identification, DCR stream recommendations
  7. **Message Size & Encoding** — UDP truncation risk (>2048 bytes), control characters, short messages
  8. **Transport Analysis** — Port usage, protocol mix (TCP/UDP), source IPs (pcap only)
- **Wireshark filter suggestions** — Clickable filters copied to clipboard
- **Export reports** to text or Markdown
- **Dark-themed WPF UI** with pass/warn/error severity badges

## Zero Dependencies

- No NuGet packages
- No Wireshark/tshark required
- No Npcap/WinPcap
- Pure managed .NET — pcap parsing, syslog/CEF parsing all built-in

## Quick Start

```powershell
# Run directly (requires .NET 10 SDK)
dotnet run --project "C:\Source\SyslogCEFAnalyzer\src\SyslogCEFAnalyzer\SyslogCEFAnalyzer.csproj"

# Build the exe
dotnet publish "C:\Source\SyslogCEFAnalyzer\src\SyslogCEFAnalyzer\SyslogCEFAnalyzer.csproj" -c Debug -o publish
```

## Supported Formats

### Input Files

| Format | Extension | How it's processed |
|---|---|---|
| pcap (libpcap) | `.pcap`, `.cap` | Extracts syslog payloads from port 514/6514/28330 |
| pcapng | `.pcapng` | Same as pcap |
| Log files | `.log`, `.txt`, `.syslog` | Parses each line as a syslog/CEF message |

### Message Formats Validated

| Format | Standard | What AMA does with it |
|---|---|---|
| RFC 3164 (BSD Syslog) | `<PRI>Mmm dd HH:mm:ss hostname tag: msg` | Ingested to **Syslog** table |
| RFC 5424 (IETF Syslog) | `<PRI>1 ISO-timestamp hostname app procid msgid SD msg` | Ingested to **Syslog** table |
| CEF | `CEF:0\|vendor\|product\|ver\|id\|name\|sev\|ext` | Ingested to **CommonSecurityLog** table |
| Cisco ASA/FTD | `%ASA-sev-msgid: text` / `%FTD-sev-msgid: text` | Ingested to **Syslog** or **CommonSecurityLog** |

## Sample Test Files

The `samples/` folder includes test files to verify the tool works:

| File | Description |
|---|---|
| `valid_rfc3164.log` | 20 well-formed BSD syslog messages |
| `valid_rfc5424.log` | 13 well-formed IETF syslog messages |
| `valid_cef.log` | 10 well-formed CEF messages from various vendors |
| `invalid_mixed.log` | Intentionally malformed messages (bad PRI, wrong pipes, missing fields) |
| `realistic_mixed.log` | Mix of all formats + noise — simulates a real `/var/log/syslog` |
| `cisco_asa_valid.log` | 15 native Cisco ASA messages with security events |
| `cisco_ftd_valid.log` | 8 native Cisco FTD messages |
| `cisco_mixed_with_cef.log` | ASA/FTD native + Cisco CEF + other vendors |

## Project Structure

```
src/SyslogCEFAnalyzer/
├── Models/Models.cs          # SyslogMessage, CefHeader, AnalysisFinding, ports
├── Parsers/
│   ├── PcapReader.cs         # Reads pcap/pcapng files
│   ├── PcapSyslogExtractor.cs # Extracts syslog payloads from packets
│   └── SyslogParser.cs       # Parses RFC 3164, RFC 5424, and CEF formats
├── Analysis/
│   ├── IAnalysisRule.cs      # Rule interface
│   ├── AnalysisEngine.cs     # Orchestrates all rules
│   └── Rules/
│       ├── FormatDetectionRule.cs
│       ├── PriValidationRule.cs
│       ├── Rfc3164ValidationRule.cs
│       ├── Rfc5424ValidationRule.cs
│       ├── CefValidationRule.cs
│       ├── CiscoAsaFtdRule.cs
│       ├── MessageSizeRule.cs
│       └── TransportAnalysisRule.cs
├── ViewModels/
│   ├── MainViewModel.cs
│   └── RelayCommand.cs
├── Converters/Converters.cs
├── Themes/Dark.xaml
├── MainWindow.xaml/cs
├── App.xaml/cs
└── GlobalUsings.cs
```

## How It Works

1. **File Loading** — Detects input type: pcap (extract payloads from syslog ports) or log file (parse lines)
2. **Message Parsing** — Each message is classified as RFC 3164, RFC 5424, CEF, or Invalid
3. **Analysis** — Eight rules validate format compliance, field presence, and encoding
4. **Display** — Results grouped by category with severity badges, recommendations, and Wireshark filters

## Security & Privacy

- **100% offline analysis** — Your files are processed locally. No data is sent to the cloud, no telemetry, no phone-home
- **No external dependencies** — Zero third-party libraries. Built entirely on .NET standard libraries
- **Standalone executable** — No installer, no registry changes, no background services
