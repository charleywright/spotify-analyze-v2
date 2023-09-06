cmake_minimum_required(VERSION 3.6)
project(needle-injector)
include(FetchContent)
set(CMAKE_CXX_STANDARD 17)

set(NEEDLE_TARGET_PLATFORM DETECT CACHE STRING "Platform to build the injector for")
set(NEEDLE_TARGET_PLATFORMS LINUX WINDOWS DETECT)
set_property(CACHE NEEDLE_TARGET_PLATFORM PROPERTY STRINGS ${NEEDLE_TARGET_PLATFORMS})
if (NOT NEEDLE_TARGET_PLATFORM IN_LIST NEEDLE_TARGET_PLATFORMS)
    message(FATAL_ERROR "Needle: Invalid target platform ${NEEDLE_TARGET_PLATFORM}, must be one of ${NEEDLE_TARGET_PLATFORMS}")
endif ()

add_executable(needle-injector
        src/main.cpp
        src/scan.cpp
        src/bootstrap.cpp
        src/file_backed_block.cpp
        src/kill.cpp
)
target_include_directories(needle-injector PRIVATE src)

if (NEEDLE_TARGET_PLATFORM STREQUAL "DETECT")
    # https://github.com/Kitware/CMake/blob/master/Modules/CMakeDetermineSystem.cmake
    message(STATUS "Needle: Detecting platform...")
    if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(NEEDLE_TARGET_PLATFORM "WINDOWS")
    elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(NEEDLE_TARGET_PLATFORM "LINUX")
    else ()
        message(FATAL_ERROR "Needle: Could not detect platform ${CMAKE_SYSTEM_NAME}")
    endif ()
endif ()
message(STATUS "Needle: Targeting ${NEEDLE_TARGET_PLATFORM}")
target_compile_definitions(needle-injector PRIVATE "NEEDLE_TARGET_${NEEDLE_TARGET_PLATFORM}")

# TODO: Open a pull request for argument termination
## Switch back from fork when https://github.com/sailormoon/flags/pull/14 is merged
#FetchContent_Declare(flags URL https://raw.githubusercontent.com/charleywright/flags/master/include/flags.h DOWNLOAD_NO_EXTRACT TRUE)
#FetchContent_MakeAvailable(flags)
#target_include_directories(needle-injector PRIVATE ${flags_SOURCE_DIR})
target_include_directories(needle-injector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Faster than git clone. There are issues with GIT_SHALLOW too on some versions of cmake
FetchContent_Declare(sigscanner URL https://github.com/charleywright/sigscanner/archive/refs/heads/master.zip DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
set(SIGSCANNER_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(SIGSCANNER_BUILD_STATIC_LIB ON CACHE BOOL "" FORCE)
set(SIGSCANNER_BUILD_EXEC OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(sigscanner)
target_link_libraries(needle-injector PRIVATE ${SIGSCANNER_STATIC_LIB})

FetchContent_Declare(elf URL https://raw.githubusercontent.com/charleywright/single-header-cpp/master/elf.hpp DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(elf)
target_include_directories(needle-injector PRIVATE ${elf_SOURCE_DIR})

# Same as above
FetchContent_Declare(fmt URL https://github.com/fmtlib/fmt/releases/download/10.0.0/fmt-10.0.0.zip DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fmt)
target_link_libraries(needle-injector PRIVATE fmt::fmt)
