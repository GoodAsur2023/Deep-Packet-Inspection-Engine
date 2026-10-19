cmake_minimum_required(VERSION 3.16)
project(AegisFlow VERSION 3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optimization flags
if(MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# 1. Packet Analyzer (L2-L4 Header Dumper)
set(ANALYZER_SOURCES
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)
add_executable(packet_analyzer ${ANALYZER_SOURCES})

# 2. AegisFlow DPI Engine (Multi-threaded Lock-Free Engine + Posture Auditor)
set(DPI_SOURCES
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/banner_extractor.cpp
    src/telemetry_emitter.cpp
    src/md5.cpp
    src/types.cpp
)
add_executable(dpi_engine ${DPI_SOURCES})

find_package(Threads REQUIRED)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)
