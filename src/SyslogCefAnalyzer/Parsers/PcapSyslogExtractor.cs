namespace SyslogCEFAnalyzer.Parsers;

using System.Net;
using System.Text;
using SyslogCEFAnalyzer.Models;

/// <summary>
/// Extracts syslog/CEF message payloads from pcap/pcapng packet captures.
/// Looks for traffic on ports 514 (TCP/UDP), 6514 (TLS-Syslog), and 28330 (AMA listener).
/// </summary>
public static class PcapSyslogExtractor
{
    public static List<SyslogMessage> ExtractFromPcap(string filePath)
    {
        var rawPackets = PcapReader.ReadFile(filePath);
        var messages = new List<SyslogMessage>();
        int msgIndex = 0;

        foreach (var raw in rawPackets)
        {
            var extracted = ExtractFromPacket(raw, msgIndex);
            if (extracted is not null)
            {
                messages.Add(extracted);
                msgIndex++;
            }
        }

        return messages;
    }

    private static SyslogMessage? ExtractFromPacket(RawPacket raw, int index)
    {
        var data = raw.Data;

        // Parse link layer
        int ipOffset = raw.LinkType switch
        {
            LinkLayerType.Ethernet => ParseEthernetOffset(data),
            LinkLayerType.LinuxSll => data.Length >= 16 ? 16 : -1,
            LinkLayerType.Raw => 0,
            _ => -1
        };

        if (ipOffset < 0 || ipOffset + 20 > data.Length) return null;

        // Parse IPv4
        byte versionIhl = data[ipOffset];
        if ((versionIhl >> 4) != 4) return null;
        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || ihl > 60 || ipOffset + ihl > data.Length) return null;

        // Standard fields are always in first 20 bytes (already validated above)
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

        // Check if either port is a known syslog port
        if (!SyslogPorts.IsSyslogPort(srcPort) && !SyslogPorts.IsSyslogPort(dstPort))
            return null;

        if (payloadOffset >= data.Length)
            return null;

        int payloadLen = data.Length - payloadOffset;
        if (payloadLen == 0) return null;

        // Extract payload as UTF-8 text
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

        // TLS-encrypted payloads (port 6514) will appear as binary/garbled data
        if ((dstPort == SyslogPorts.SyslogTls || srcPort == SyslogPorts.SyslogTls) &&
            payload.Any(c => c == '\0' || (char.IsControl(c) && c is not '\n' and not '\r' and not '\t')))
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
            return tlsMsg;
        }

        // A single UDP datagram or TCP segment may contain one syslog message
        // For simplicity, treat each payload as one message (TCP reassembly is out of scope)
        var msg = SyslogParser.ParseLine(payload, index, InputSource.PcapFile);
        msg.PacketTimestamp = raw.Timestamp;
        msg.SourceIp = srcIp;
        msg.DestIp = dstIp;
        msg.SourcePort = srcPort;
        msg.DestPort = dstPort;
        msg.Protocol = protoName;

        return msg;
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
        return etherType == 0x0800 ? offset : -1; // IPv4 only
    }

    private static ushort ReadBE16(byte[] data, int offset) =>
        (ushort)((data[offset] << 8) | data[offset + 1]);
}
