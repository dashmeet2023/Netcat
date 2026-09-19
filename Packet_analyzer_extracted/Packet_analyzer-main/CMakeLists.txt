cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release if no build type specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Release optimisation flags
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

# Find Threads library (required for multi-threaded pipeline)
find_package(Threads REQUIRED)

# Source files for the DPI engine executable
set(SOURCES
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executable target
add_executable(dpi_engine ${SOURCES})

# Link the Threads library
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# Static MinGW runtime — bake libgcc, libstdc++ and libwinpthread into the
# exe so it runs without any MinGW DLLs present on the target machine.
# These flags only apply on MinGW/GCC; MSVC ignores them safely.
# ---------------------------------------------------------------------------
if(MINGW OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(dpi_engine PRIVATE
        -static-libgcc
        -static-libstdc++
        -static                  # also pulls in libwinpthread statically
    )
endif()
