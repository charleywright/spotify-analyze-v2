cmake_minimum_required(VERSION 3.10)
include(FetchContent)
project(needle)
set(CMAKE_CXX_STANDARD 17)

set(NEEDLE_COMPACT_PROTO OFF CACHE BOOL "Print the compact version of protobuf messages")
set(NEEDLE_COMPACT_PI OFF CACHE BOOL "Print ProductInfo as XML without formatting")
set(NEEDLE_JSON_PI OFF CACHE BOOL "Convert ProductInfo to a JSON object")
set(NEEDLE_HIDE_PINGS OFF CACHE BOOL "Hide ping/pong messages")

file(GLOB_RECURSE SrcFiles "${CMAKE_CURRENT_SOURCE_DIR}/src/**.cpp")
add_library(needle MODULE ${SrcFiles})
target_include_directories(needle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE InjectorSrcFiles "${CMAKE_CURRENT_SOURCE_DIR}/injector/**.cpp")
add_executable(needle-injector ${InjectorSrcFiles})
target_include_directories(needle-injector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/injector)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(needle PRIVATE dl)
    set_property(TARGET needle PROPERTY POSITION_IN ON)
    set_property(TARGET needle PROPERTY PREFIX "")
    set_property(TARGET needle PROPERTY OUTPUT_NAME needle)
    set_property(TARGET needle PROPERTY SUFFIX .so)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Workaround for VS Build Tools making Debug and Release directories
    set_target_properties(needle PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<0:>)
    set_target_properties(needle-injector PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<0:>)
endif ()

if (NEEDLE_COMPACT_PROTO)
    target_compile_definitions(needle PRIVATE NEEDLE_COMPACT_PROTO=1)
endif ()
if (NEEDLE_COMPACT_PI)
    target_compile_definitions(needle PRIVATE NEEDLE_COMPACT_PI=1)
endif ()
if (NEEDLE_JSON_PI)
    target_compile_definitions(needle PRIVATE NEEDLE_JSON_PI=1)
endif ()
if (NEEDLE_HIDE_PINGS)
    target_compile_definitions(needle PRIVATE NEEDLE_HIDE_PINGS)
endif ()

set(SUBHOOK_STATIC ON)
set(SUBHOOK_INSTALL OFF)
set(SUBHOOK_TESTS OFF)
set(SUBHOOK_FORCE_32BIT ON)
FetchContent_Declare(subhook
        GIT_REPOSITORY https://github.com/Zeex/subhook
        GIT_TAG e935959d2f9cc642bcbb5e7759b2b1e7196b0947
        )
FetchContent_MakeAvailable(subhook)
target_link_libraries(needle PRIVATE subhook)

find_package(Protobuf REQUIRED CONFIG)
file(GLOB_RECURSE ProtoFiles "${CMAKE_CURRENT_SOURCE_DIR}/proto/**.proto")
protobuf_generate(
        LANGUAGE cpp
        TARGET needle
        IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/proto
        PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto"
        OUT_VAR PROTO_GENERATED_FILES
        PROTOS ${ProtoFiles})
set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
target_link_libraries(needle PRIVATE protobuf::libprotobuf)
target_include_directories(needle PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/proto)

FetchContent_Declare(pugixml
        GIT_REPOSITORY https://github.com/zeux/pugixml
        GIT_TAG 1dc3266fffdb1f37961172c5c96af2f7e6132789
        )
FetchContent_MakeAvailable(pugixml)
target_include_directories(needle PRIVATE ${pugixml_SOURCE_DIR}/src)
target_link_libraries(needle PRIVATE pugixml-static)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp DOWNLOAD_NO_EXTRACT YES)
FetchContent_MakeAvailable(json)
target_include_directories(needle PRIVATE ${json_SOURCE_DIR})

FetchContent_Declare(flags URL https://raw.githubusercontent.com/sailormoon/flags/master/include/flags.h DOWNLOAD_NO_EXTRACT YES)
FetchContent_MakeAvailable(flags)
target_include_directories(needle-injector PRIVATE ${flags_SOURCE_DIR})

FetchContent_Declare(fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt
        GIT_TAG 3160847ebd594115743a53230e5f5b697a74f733
        )
FetchContent_MakeAvailable(fmt)
target_link_libraries(needle PRIVATE fmt)
target_link_libraries(needle-injector PRIVATE fmt)
target_include_directories(needle PRIVATE ${fmt_SOURCE_DIR}/include)
target_include_directories(needle-injector PRIVATE ${fmt_SOURCE_DIR}/include)
