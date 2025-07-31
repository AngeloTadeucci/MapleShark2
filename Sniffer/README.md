# MapleStory2 Packet Sniffer Console Application

A standalone console application that captures, decrypts, and outputs MapleStory2 network packets in JSON format for consumption by Node.js applications.

**✅ Standalone Executable**: No dependencies on MapleShark2 UI project - all necessary code has been copied and integrated.

## Features

- **Network Packet Capture**: Uses SharpPcap to capture TCP packets on specified port ranges
- **TCP Stream Reassembly**: Reconstructs fragmented TCP packets using the existing TcpReassembler
- **MapleStory2 Decryption**: Decrypts packets using the MapleCipher.Decryptor from Maple2.PacketLib
- **JSON Output**: Outputs structured packet data suitable for Node.js consumption
- **Configurable**: Supports both command-line arguments and configuration files
- **Auto-detection**: Automatically selects the first active network interface if none specified

## Usage

### Command Line Options

```bash
# Show help
dotnet run -- --help

# List available network interfaces
dotnet run -- --list-interfaces

# Run with specific interface and port range
dotnet run -- --interface "\Device\NPF_{99739CE7-73C3-42AF-A895-DDAE4745CC88}" --low-port 20000 --high-port 33001

# Run with default settings (auto-detects interface)
dotnet run
```

### Configuration File

Create a `sniffer-config.json` file in the application directory:

```json
{
  "interface": "",
  "lowPort": 20000,
  "highPort": 33001,
  "packetRate": 100
}
```

- `interface`: Network interface name (leave empty for auto-detection)
- `lowPort`: Lower bound of port range to monitor
- `highPort`: Upper bound of port range to monitor  
- `packetRate`: Packet processing interval in milliseconds

### Output Format

The application outputs one JSON object per line to stdout:

```json
{
  "timestamp": "2024-07-31T10:30:45.123Z",
  "outbound": false,
  "opcode": 1,
  "name": "RequestVersion",
  "build": 12345,
  "data": "0A0B0C0D..."
}
```

- `timestamp`: When the packet was captured
- `outbound`: Whether the packet was sent from client (true) or server (false)
- `opcode`: MapleStory2 packet opcode
- `name`: Packet name (RequestVersion for handshake, Unknown_XXXX for others)
- `build`: MapleStory2 client build version
- `data`: Hex-encoded packet payload data

## Integration with Node.js

The JSON output can be easily consumed by Node.js applications:

```javascript
const { spawn } = require('child_process');

const sniffer = spawn('dotnet', ['run'], {
  cwd: 'path/to/Sniffer',
  stdio: ['ignore', 'pipe', 'pipe']
});

sniffer.stdout.on('data', (data) => {
  const lines = data.toString().split('\n');
  for (const line of lines) {
    if (line.trim()) {
      try {
        const packet = JSON.parse(line);
        console.log(`[${packet.outbound ? 'OUT' : 'IN'}] ${packet.name} (${packet.opcode})`);
        // Process packet data...
      } catch (e) {
        // Ignore non-JSON lines (logs, etc.)
      }
    }
  }
});
```

## Requirements

- .NET 8.0 Runtime (one-time installation)
- Windows (required for SharpPcap)
- MapleStory2 client running and connected to a server

## Building

### Development Build
```bash
dotnet build
```

### Single-File Executable
```bash
dotnet publish -c Release
```

This creates a framework-dependent executable at:
`bin/Release/net8.0-windows/win-x64/publish/MapleStory2Sniffer.exe`

## Session Management

The application intelligently manages packet capture sessions:

- **Active Session Tracking**: Sessions remain active as long as packets are being received
- **Graceful Timeout**: Empty sessions are closed after 5 seconds (no packets received)
- **Inactivity Timeout**: Sessions with no activity for 30+ seconds are automatically closed
- **TCP Termination**: Sessions are properly closed when TCP FIN/RST packets are received

## Notes

- The application must be run with administrator privileges to capture network packets
- Only TCP packets within the specified port range are captured
- The application automatically handles MapleStory2 encryption and packet reassembly
- Sessions will stay active as long as packets are flowing (fixed premature session termination)
- Logs are written to both console and `sniffer.log` file
- Press Ctrl+C to stop the application gracefully

## Troubleshooting

**Sessions terminating too early**: This has been fixed in the current version. Sessions now properly track packet activity and only close when truly inactive.

**No packets captured**: Ensure you're running as administrator and that MapleStory2 is actively connected to a server within the configured port range.
