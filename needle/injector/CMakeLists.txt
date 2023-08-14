cmake_minimum_required(VERSION 3.6)
project(needle-injector)
include(FetchContent)
set(CMAKE_CXX_STANDARD 17)

add_executable(needle-injector
        src/main.cpp
        src/scan.cpp
        src/bootstrap.cpp
)
target_include_directories(needle-injector PRIVATE src)

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

# Same as above
FetchContent_Declare(fmt URL https://github.com/fmtlib/fmt/releases/download/10.0.0/fmt-10.0.0.zip DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fmt)
target_link_libraries(needle-injector PRIVATE fmt::fmt)
