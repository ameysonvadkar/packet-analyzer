cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 2.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# Core library (shared by all targets)
# ============================================================================
set(CORE_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/rule_manager.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/dpi_engine.cpp
)

add_library(dpi_core STATIC ${CORE_SOURCES})

# ============================================================================
# Target 1: Simple packet analyzer (single-threaded, learning/debug)
# ============================================================================
add_executable(packet_analyzer src/main.cpp)
target_link_libraries(packet_analyzer dpi_core)

# ============================================================================
# Target 2: Single-threaded DPI engine (working version)
# ============================================================================
add_executable(dpi_simple src/main_working.cpp)
target_link_libraries(dpi_simple dpi_core)

# ============================================================================
# Target 3: Multi-threaded DPI engine (self-contained)
# ============================================================================
add_executable(dpi_mt src/dpi_mt.cpp)
target_link_libraries(dpi_mt dpi_core)

# ============================================================================
# Target 4: Full modular DPI engine (production)
# ============================================================================
add_executable(dpi_engine src/main_dpi.cpp)
target_link_libraries(dpi_engine dpi_core)

# ============================================================================
# Target 5: DPI Daemon with live capture, UDP control & stats streaming
# ============================================================================
add_executable(dpi_daemon src/main_daemon.cpp src/pcap_live_capturer.cpp)
target_link_libraries(dpi_daemon dpi_core)

# Find and link pcap for live capture
find_library(PCAP_LIBRARY pcap)
if(PCAP_LIBRARY)
    target_link_libraries(dpi_daemon ${PCAP_LIBRARY})
    target_compile_definitions(dpi_daemon PRIVATE HAS_LIBPCAP=1)
    message(STATUS "Found libpcap: ${PCAP_LIBRARY}")
else()
    message(WARNING "libpcap not found - live capture will be disabled")
endif()

# Platform-specific settings
if(APPLE)
    # macOS has pcap pre-installed
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(dpi_core pthread)
endif()
