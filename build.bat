@echo off
set "PATH=C:\msys64\mingw64\bin;%PATH%"

echo ==============================================
echo Building AegisFlow DPI Engine (dpi_engine.exe)...
echo ==============================================
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/banner_extractor.cpp src/telemetry_emitter.cpp src/md5.cpp src/types.cpp -lpcap -lws2_32
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build of dpi_engine.exe failed!
    exit /b %ERRORLEVEL%
)
echo [OK] dpi_engine.exe built successfully.

echo.
echo ==============================================
echo Building Packet Analyzer (packet_analyzer.exe)...
echo ==============================================
g++ -std=c++17 -O2 -I include -o packet_analyzer.exe src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp -lpcap -lws2_32
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build of packet_analyzer.exe failed!
    exit /b %ERRORLEVEL%
)
echo [OK] packet_analyzer.exe built successfully.

echo.
echo ==============================================
echo Building & Running Unit Tests (test_engine.exe)...
echo ==============================================
g++ -std=c++17 -O2 -I include -o test_engine.exe tests/test_engine.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/banner_extractor.cpp src/telemetry_emitter.cpp src/md5.cpp src/types.cpp -lgtest -lgtest_main -lpcap -lws2_32
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build of test_engine.exe failed!
    exit /b %ERRORLEVEL%
)
test_engine.exe
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Unit tests failed!
    exit /b %ERRORLEVEL%
)
echo [OK] test_engine.exe passed all unit tests!

echo.
echo ==============================================
echo Build complete! You can now run:
echo   dpi_engine.exe test_dpi.pcap output.pcap
echo   dpi_engine.exe --list-interfaces
echo   python control_plane\cve_remediator.py --alerts alerts.jsonl
echo ==============================================
