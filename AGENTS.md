# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## Read first

`docs/CAMPAIGN.md` — the 2026-07 improvement-campaign record. It holds the measured evidence behind the
manifest/resolver/invariants machinery, the killed-proposals ledger (**consult §4 and §5 Phase 3 before
proposing changes** — plausible ideas listed there already died under measurement), and the remaining
open items (§9). Don't re-derive any of it.

## Build & Run

```bash
# Build entire solution
dotnet build MapleShark2.sln

# Run GUI application
dotnet run --project MapleShark2/MapleShark2.csproj

# Run CLI sniffer
dotnet run --project Sniffer/Sniffer.csproj -- --list-interfaces
dotnet run --project Sniffer/Sniffer.csproj

# Publish release builds
dotnet publish MapleShark2/MapleShark2.csproj -c Release          # Framework-dependent
dotnet publish Sniffer/Sniffer.csproj -c Release                  # Single-file exe (win-x64)
```

Standalone test consoles live in `Tests/` (`SegmentByteReaderTests`, `PerfLogTests`) — plain exes
compiling the source under test directly; run each with `dotnet run -c Release`. They are deliberately
not in the .sln and use no test framework.

**Requirements:** Windows only (SharpPcap + WinForms). Administrator privileges required for packet capture. .NET 8.0 SDK.

## Architecture

Three projects sharing packet logic through a library:

```
MapleShark2.sln
├── Maple2.PacketLib   (netstandard2.1) — git submodule; crypto + binary I/O
├── MapleShark2        (net8.0-windows) — WinForms GUI packet analyzer
└── Sniffer            (net8.0-windows) — Standalone CLI sniffer
```

### Maple2.PacketLib (submodule)

Core library used by both applications:
- `Crypto/` — `MapleCipher` (main entry point with `Encryptor`/`Decryptor` inner classes), `XORCrypter`, `TableCrypter`, `RearrangeCrypter`, `Rand32`
- `Tools/` — `ByteReader`/`ByteWriter` with pooled variants, `MapleStream` (packet stream management), `HexEncoding`

### MapleShark2 (GUI)

WinForms application with DockPanelSuite layout. Startup sequence: `SplashForm` → `SetupForm` → `MainForm`.

- `UI/MainForm.cs` — Orchestrates packet capture via SharpPcap; manages sessions
- `UI/SessionForm.cs` — Displays packets for a single captured TCP session
- `UI/DataForm.cs` — Hex viewer (Be.Windows.Forms.HexBox)
- `UI/StructureForm.cs` — Shows parsed packet fields from Python scripts
- `Tools/ScriptManager.cs` — IronPython 3.4.1 engine; loads scripts from `%AppData%/MapleShark2/Scripts/`
- `Tools/TcpReassembler.cs` — Reassembles TCP streams from raw pcap captures
- `Tools/Config.cs` — Reads/writes `Config.xml`; stores interface, port range (default 20000–33001), packet rate, theme
- `Tools/PerfLog.cs` — Perf instrumentation (timing scopes, UI-hang watchdog, counters) → `perf.log`
- `Logging/MaplePacket.cs` — In-memory packet representation
- `Logging/DefinitionsContainer.cs` — Loads opcode definitions from `%AppData%/MapleShark2/`
- `Resources/script_api.py` — Python API imported into every script; provides field-reading helpers

**Key dependencies:** SharpPcap 6.2.5, PacketDotNet 1.4.7, IronPython 3.4.1, DockPanelSuite 3.1.0, NLog 5.2.3, Costura.Fody 5.7.0 (embeds all DLLs into the exe)

### Sniffer (CLI)

Standalone console app for headless packet capture; intended for Node.js integration via JSON stdout.

- `Program.cs` — Main capture loop; outputs JSON lines per packet
- `PacketSession.cs` — TCP session management with configurable timeout
- `SnifferConfig.cs` — Config loaded from `sniffer-config.json`

**Key dependencies:** SharpPcap, PacketDotNet, Serilog

## Configuration

**GUI** (`Config.xml` in `%AppData%/MapleShark2/`):
- `Interface` — Network device name for capture
- `LowPort`/`HighPort` — Port range filter (default: 20000–33001)
- `PacketRate` — Polling interval in ms (default: 300)
- `WindowTheme` — Light | Dark

**Sniffer** (`sniffer-config.json` next to executable, see `sniffer-config.json.example`):
- Same fields as GUI config but `packetRate` defaults to 100ms

## Packet Scripting

Python scripts (IronPython 3.4.1) placed in `%AppData%/MapleShark2/Scripts/` define how packet opcodes are parsed into named fields. `script_api.py` is auto-imported and provides the field-reading API. Scripts can be version- and locale-specific.
