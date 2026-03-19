namespace SyslogCEFAnalyzer.Parsers;

using System.Net;
using System.Text;
using SyslogCEFAnalyzer.Models;

/// <summary>
/// Extracts syslog/CEF message payloads from pcap/pcapng packet captures.
/// Supports TCP stream reassembly and ports 514, 6514, 28330.
/// </summary>
public static class PcapSyslogExtractor
{
    /// <summary>
    /// Extract syslog messages from a pcap file. Returns messages and parse warnings.
    /// </summary>
    public static (List<SyslogMessage> Messages, List<string> Warnings) ExtractFromPcap(string filePath)
    {
        var (rawPackets, warnings) = PcapReader.ReadFile(filePath);
        var messages = new List<SyslogMessage>();
        int msgIndex = 0;

        // TCP stream reassembly buffers keyed by flow (srcIP:srcPort → dstIP:dstPort)
        var tcpStreams = new Dictionary<string, TcpStreamBuffer>();

        foreach (var raw in rawPackets)
        {
            var result = ExtractFromPacket(raw, ref msgIndex, tcpStreams);
            if (result != null)
                messages.AddRange(result);
        }

        // Flush remaining TCP stream buffers
        foreach (var kvp in tcpStreams)
        {
            var buffer = kvp.Value;
            var flushed = FlushTcpBuffer(buffer, ref msgIndex);
            messages.AddRange(flushed);
        }

        if (tcpStreams.Count > 0)
        {
            int reassembledCount = messages.Count(m => m.Protocol == "TCP");
            if (reassembledCount > 0)
                warnings.Add($"TCP stream reassembly: processed {tcpStreams.Count} TCP flows, extracted {reassembledCount} messages.");
        }

        return (messages, warnings);
    }

    private static List<SyslogMessage>? ExtractFromPacket(RawPacket raw, ref int index, Dictionary<string, TcpStreamBuffer> tcpStreams)
    {
        var data = raw.Data;

        int ipOffset = raw.LinkType switch
        {
            LinkLayerType.Ethernet => ParseEthernetOffset(data),
            LinkLayerType.LinuxSll => data.Length >= 16 ? 16 : -1,
            LinkLayerType.Raw => 0,
            _ => -1
        };

        if (ipOffset < 0 || ipOffset + 20 > data.Length) return null;

        byte versionIhl = data[ipOffset];
        if ((versionIhl >> 4) != 4) return null;
        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || ihl > 60 || ipOffset + ihl > data.Length) return null;

        byte protocol = data[ipOffset + 9];
        string srcIp = new IPAddress(new ReadOnlySpan<byte>(data, ipOffset + 12, 4)).ToString();
        string dstIp = new IPAddress(new ReadOnlySpan<byte>(data, ipOffset + 16, 4)).ToString();

        int transportOffset = ipOffset + ihl;
        ushort srcPort, dstPort;
        int payloadOffset;
        string protoName;

        if (protocol == 6) // TCP
        {
            if (transportOffset + 20 > data.Length) return null;
            srcPort = ReadBE16(data, transportOffset);
            dstPort = ReadBE16(data, transportOffset + 2);
            int dataOff = ((data[transportOffset + 12] >> 4) & 0x0F) * 4;
            if (dataOff < 20 || transportOffset + dataOff > data.Length) return null;
            payloadOffset = transportOffset + dataOff;
            protoName = "TCP";
        }
        else if (protocol == 17) // UDP
        {
            if (transportOffset + 8 > data.Length) return null;
            srcPort = ReadBE16(data, transportOffset);
            dstPort = ReadBE16(data, transportOffset + 2);
            payloadOffset = transportOffset + 8;
            protoName = "UDP";
        }
        else
        {
            return null;
        }

        if (!SyslogPorts.IsSyslogPort(srcPort) && !SyslogPorts.IsSyslogPort(dstPort))
            return null;

        if (payloadOffset >= data.Length)
            return null;

        int payloadLen = data.Length - payloadOffset;
        if (payloadLen == 0) return null;

        // TLS-encrypted payloads (port 6514) detection
        if ((dstPort == SyslogPorts.SyslogTls || srcPort == SyslogPorts.SyslogTls) &&
            HasBinaryContent(data, payloadOffset, payloadLen))
        {
            var tlsMsg = SyslogParser.ParseLine("", index, InputSource.PcapFile);
            tlsMsg.DetectedFormat = SyslogFormat.Invalid;
            tlsMsg.ValidationErrors.Add("Payload appears to be TLS-encrypted (port 6514). This tool cannot decrypt TLS traffic.");
            tlsMsg.PacketTimestamp = raw.Timestamp;
            tlsMsg.SourceIp = srcIp;
            tlsMsg.DestIp = dstIp;
            tlsMsg.SourcePort = srcPort;
            tlsMsg.DestPort = dstPort;
            tlsMsg.Protocol = protoName;
            index++;
            return [tlsMsg];
        }

        // TCP stream reassembly
        if (protoName == "TCP")
        {
            string flowKey = $"{srcIp}:{srcPort}->{dstIp}:{dstPort}";

            if (!tcpStreams.TryGetValue(flowKey, out var buffer))
            {
                buffer = new TcpStreamBuffer
                {
                    SrcIp = srcIp, DstIp = dstIp,
                    SrcPort = srcPort, DstPort = dstPort,
                    FirstTimestamp = raw.Timestamp
                };
                tcpStreams[flowKey] = buffer;
            }

            buffer.AppendPayload(data, payloadOffset, payloadLen);
            buffer.LastTimestamp = raw.Timestamp;

            // Try to extract complete syslog messages (newline-delimited for TCP)
            var extracted = ExtractFromTcpBuffer(buffer, ref index);
            return extracted.Count > 0 ? extracted : null;
        }

        // UDP: single datagram = single message
        string payload;
        try
        {
            payload = Encoding.UTF8.GetString(data, payloadOffset, payloadLen).Trim('\0').Trim();
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(payload)) return null;

        var msg = SyslogParser.ParseLine(payload, index, InputSource.PcapFile);
        msg.PacketTimestamp = raw.Timestamp;
        msg.SourceIp = srcIp;
        msg.DestIp = dstIp;
        msg.SourcePort = srcPort;
        msg.DestPort = dstPort;
        msg.Protocol = protoName;
        index++;

        return [msg];
    }

    /// <summary>Extract complete newline-delimited messages from a TCP stream buffer.</summary>
    private static List<SyslogMessage> ExtractFromTcpBuffer(TcpStreamBuffer buffer, ref int index)
    {
        var results = new List<SyslogMessage>();
        const int MaxBufferSize = 256 * 1024; // 256 KB max per stream

        // Prevent unbounded growth
        if (buffer.Data.Length > MaxBufferSize)
        {
            buffer.Data.Clear();
            return results;
        }

        string current = buffer.GetString();

        // TCP syslog uses newline as message delimiter (RFC 6587 non-transparent framing)
        while (true)
        {
            int nlPos = current.IndexOf('\n');
            if (nlPos < 0) break;

            string line = current[..nlPos].TrimEnd('\r').Trim('\0').Trim();
            current = current[(nlPos + 1)..];

            if (string.IsNullOrWhiteSpace(line)) continue;

            var msg = SyslogParser.ParseLine(line, index, InputSource.PcapFile);
            msg.PacketTimestamp = buffer.FirstTimestamp;
            msg.SourceIp = buffer.SrcIp;
            msg.DestIp = buffer.DstIp;
            msg.SourcePort = buffer.SrcPort;
            msg.DestPort = buffer.DstPort;
            msg.Protocol = "TCP";
            results.Add(msg);
            index++;
        }

        // Keep remaining partial data in buffer
        buffer.SetFromString(current);

        return results;
    }

    /// <summary>Flush any remaining data in a TCP stream buffer as a final message.</summary>
    private static List<SyslogMessage> FlushTcpBuffer(TcpStreamBuffer buffer, ref int index)
    {
        var results = new List<SyslogMessage>();
        string remaining = buffer.GetString().Trim('\0').Trim();

        if (string.IsNullOrWhiteSpace(remaining)) return results;

        // Could be multiple newline-delimited messages
        foreach (string line in remaining.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string trimmed = line.TrimEnd('\r').Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;

            var msg = SyslogParser.ParseLine(trimmed, index, InputSource.PcapFile);
            msg.PacketTimestamp = buffer.LastTimestamp;
            msg.SourceIp = buffer.SrcIp;
            msg.DestIp = buffer.DstIp;
            msg.SourcePort = buffer.SrcPort;
            msg.DestPort = buffer.DstPort;
            msg.Protocol = "TCP";
            results.Add(msg);
            index++;
        }

        return results;
    }

    private static bool HasBinaryContent(byte[] data, int offset, int length)
    {
        int checkLen = Math.Min(length, 64);
        for (int i = offset; i < offset + checkLen && i < data.Length; i++)
        {
            byte b = data[i];
            if (b == 0 || (b < 0x20 && b != 0x0A && b != 0x0D && b != 0x09))
                return true;
        }
        return false;
    }

    private static int ParseEthernetOffset(byte[] data)
    {
        if (data.Length < 14) return -1;
        ushort etherType = ReadBE16(data, 12);
        int offset = 14;
        if (etherType == 0x8100 && data.Length >= 18) // VLAN
        {
            etherType = ReadBE16(data, 16);
            offset = 18;
        }
        return etherType == 0x0800 ? offset : -1;
    }

    private static ushort ReadBE16(byte[] data, int offset) =>
        (ushort)((data[offset] << 8) | data[offset + 1]);

    /// <summary>Buffers TCP stream data for reassembly.</summary>
    private sealed class TcpStreamBuffer
    {
        public string SrcIp { get; init; } = "";
        public string DstIp { get; init; } = "";
        public ushort SrcPort { get; init; }
        public ushort DstPort { get; init; }
        public DateTime FirstTimestamp { get; init; }
        public DateTime LastTimestamp { get; set; }
        public StringBuilder Data { get; } = new();

        public void AppendPayload(byte[] data, int offset, int length)
        {
            try
            {
                string text = Encoding.UTF8.GetString(data, offset, length);
                Data.Append(text);
            }
            catch (ArgumentException)
            {
                // Skip non-UTF8 segments
            }
        }

        public string GetString() => Data.ToString();

        public void SetFromString(string remaining)
        {
            Data.Clear();
            Data.Append(remaining);
        }
    }
}
