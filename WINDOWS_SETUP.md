# Windows Setup Guide - AegisFlow DPI & Posture Engine

This guide walks you through building and running AegisFlow on Windows.

---

## Quick Start (Easiest Method)

If you already have MinGW-w64 (GCC) or MSYS2 installed:

1. Open PowerShell or Command Prompt in the project directory.
2. Run the automated build script:
   ```cmd
   .\build.bat
   ```
   Or in PowerShell:
   ```powershell
   .\build.ps1
   ```
3. Run the engine against test traffic:
   ```powershell
   .\dpi_engine.exe test_dpi.pcap output_filtered.pcap
   ```
4. Run the Python control plane to analyze alerts and generate remediation playbooks:
   ```powershell
   python control_plane\cve_remediator.py --alerts alerts.jsonl
   ```

---

## Option 1: Using MinGW-w64 via MSYS2

### Step 1: Install MSYS2 & Compiler
1. Download and install MSYS2 from [msys2.org](https://www.msys2.org/).
2. Open **MSYS2 MINGW64** from the Start Menu.
3. Install the MinGW-w64 GCC toolchain:
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
   ```
4. Add `C:\msys64\mingw64\bin` to your User `PATH` environment variable.

### Step 2: Build the Targets
Open PowerShell or Command Prompt:
```cmd
g++ -std=c++17 -O2 -I include -o dpi_engine.exe ^
    src/dpi_mt.cpp ^
    src/pcap_reader.cpp ^
    src/packet_parser.cpp ^
    src/sni_extractor.cpp ^
    src/banner_extractor.cpp ^
    src/telemetry_emitter.cpp ^
    src/md5.cpp ^
    src/types.cpp
```

And to build the standalone packet header analyzer:
```cmd
g++ -std=c++17 -O2 -I include -o packet_analyzer.exe ^
    src/main.cpp ^
    src/pcap_reader.cpp ^
    src/packet_parser.cpp
```

---

## Option 2: Using Visual Studio (MSVC)

### Step 1: Install Visual Studio 2022
1. Install **Visual Studio 2022 Community** with the **Desktop development with C++** workload.

### Step 2: Build from Developer Command Prompt
Open **Developer Command Prompt for VS 2022** and run:
```cmd
cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe ^
    src\dpi_mt.cpp ^
    src\pcap_reader.cpp ^
    src\packet_parser.cpp ^
    src\sni_extractor.cpp ^
    src\banner_extractor.cpp ^
    src\telemetry_emitter.cpp ^
    src\md5.cpp ^
    src\types.cpp
```

---

## Option 3: Using CMake
```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

---

## Testing & Verifying

### 1. Generate Synthetic Security Traffic
```powershell
python generate_test_pcap.py
```
This generates `test_dpi.pcap` with:
- Modern TLS 1.2 / 1.3 ClientHello handshakes (Google, YouTube, GitHub, Discord, Amazon, Apple, etc.)
- Deprecated TLS 1.0 ClientHello with weak RC4 and 3DES cipher suites
- Passive service banners: OpenSSH 7.4p1 (CVE-2016-10009) and Apache 2.4.49 (CVE-2021-41773)
- Plaintext HTTP requests and DNS queries

### 2. Run Flow Filtering & Posture Auditing
```powershell
# Block YouTube and specific IP
.\dpi_engine.exe test_dpi.pcap output_filtered.pcap --block-app YouTube --block-ip 192.168.1.50
```

### 3. Generate Remediation Playbook
```powershell
python control_plane\cve_remediator.py --alerts alerts.jsonl --export-md remediation_playbook.md
```
