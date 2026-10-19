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

# Optional libpcap support
find_library(PCAP_LIB NAMES pcap wpcap)
if(PCAP_LIB)
    set(PCAP_LIBRARIES ${PCAP_LIB})
    if(WIN32)
        list(APPEND PCAP_LIBRARIES ws2_32)
    endif()
    message(STATUS "Found pcap library: ${PCAP_LIB}")
else()
    set(PCAP_LIBRARIES "")
    message(STATUS "pcap library not found; live capture disabled, offline PCAP enabled.")
endif()

target_link_libraries(packet_analyzer PRIVATE ${PCAP_LIBRARIES})
target_link_libraries(dpi_engine PRIVATE Threads::Threads ${PCAP_LIBRARIES})

# 3. Unit Test Suite (GoogleTest)
option(BUILD_TESTING "Build the testing tree" ON)
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    set(TEST_SOURCES
        tests/test_engine.cpp
        src/pcap_reader.cpp
        src/packet_parser.cpp
        src/sni_extractor.cpp
        src/banner_extractor.cpp
        src/telemetry_emitter.cpp
        src/md5.cpp
        src/types.cpp
    )
    add_executable(test_engine ${TEST_SOURCES})
    target_link_libraries(test_engine PRIVATE GTest::gtest GTest::gtest_main Threads::Threads ${PCAP_LIBRARIES})
    add_test(NAME AegisFlowTestSuite COMMAND test_engine)
endif()

