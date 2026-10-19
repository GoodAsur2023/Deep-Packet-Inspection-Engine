# Build script for AegisFlow DPI Engine & Packet Analyzer
$ErrorActionPreference = "Stop"
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Building AegisFlow DPI Engine (dpi_engine.exe)..." -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/banner_extractor.cpp src/telemetry_emitter.cpp src/md5.cpp src/types.cpp
Write-Host "[OK] dpi_engine.exe built successfully.`n" -ForegroundColor Green

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Building Packet Analyzer (packet_analyzer.exe)..." -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
g++ -std=c++17 -O2 -I include -o packet_analyzer.exe src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp
Write-Host "[OK] packet_analyzer.exe built successfully.`n" -ForegroundColor Green

Write-Host "Build complete! You can now run:" -ForegroundColor Yellow
Write-Host "  .\dpi_engine.exe test_dpi.pcap output.pcap" -ForegroundColor White
Write-Host "  python control_plane\cve_remediator.py --alerts alerts.jsonl" -ForegroundColor White
