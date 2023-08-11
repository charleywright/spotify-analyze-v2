cmake_minimum_required(VERSION 3.6)
project(needle-injector)
include(FetchContent)
set(CMAKE_CXX_STANDARD 17)

add_executable(needle-injector
        src/main.cpp
        src/scan.cpp
)
target_include_directories(needle-injector PRIVATE src)

# Switch back from fork when https://github.com/sailormoon/flags/pull/14 is merged
FetchContent_Declare(flags URL https://raw.githubusercontent.com/charleywright/flags/master/include/flags.h DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(flags)
target_include_directories(needle-injector PRIVATE ${flags_SOURCE_DIR})

# Faster than git clone. There are issues with GIT_SHALLOW too on some versions of cmake
FetchContent_Declare(sigscanner URL https://github.com/charleywright/sigscanner/archive/refs/heads/master.zip DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
set(SIGSCANNER_SHARED_LIB OFF)
set(SIGSCANNER_STATIC_LIB ON)
set(SIGSCANNER_BUILD_EXEC OFF)
FetchContent_MakeAvailable(sigscanner)
target_include_directories(needle-injector PRIVATE ${SIGSCANNER_INCLUDE_DIRS})
target_link_libraries(needle-injector PRIVATE ${SIGSCANNER_STATIC_LIB})
