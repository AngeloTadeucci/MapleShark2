using System.Text.Json.Serialization;

namespace Sniffer;

public class SnifferConfig {
    [JsonPropertyName("interface")]
    public string Interface { get; set; } = "";
    
    [JsonPropertyName("lowPort")]
    public ushort LowPort { get; set; } = 20000;
    
    [JsonPropertyName("highPort")]
    public ushort HighPort { get; set; } = 33001;
    
    [JsonPropertyName("packetRate")]
    public int PacketRate { get; set; } = 100; // Processing interval in milliseconds
}
