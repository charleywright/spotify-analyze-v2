cmake_minimum_required(VERSION 3.2)
include(FetchContent)
project(needle)

set(NEEDLE_COMPACT_PROTO OFF CACHE BOOL "Print the compact version of protobuf messages")
set(NEEDLE_COMPACT_PI OFF CACHE BOOL "Print ProductInfo as XML without formatting")
set(NEEDLE_JSON_PI OFF CACHE BOOL "Convert ProductInfo to a JSON object")
set(NEEDLE_HIDE_PINGS OFF CACHE BOOL "Hide ping/pong messages")

file(GLOB_RECURSE SrcFiles "${CMAKE_CURRENT_SOURCE_DIR}/src/**.cpp")
add_library(needle MODULE ${SrcFiles})
target_include_directories(needle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(needle PRIVATE dl)
set_property(TARGET needle PROPERTY POSITION_IN ON)
set_property(TARGET needle PROPERTY PREFIX "")
set_property(TARGET needle PROPERTY OUTPUT_NAME needle)
set_property(TARGET needle PROPERTY SUFFIX .so)

if(NEEDLE_COMPACT_PROTO)
    target_compile_definitions(needle PRIVATE NEEDLE_COMPACT_PROTO=1)
endif()
if(NEEDLE_COMPACT_PI)
    target_compile_definitions(needle PRIVATE NEEDLE_COMPACT_PI=1)
endif()
if(NEEDLE_JSON_PI)
    target_compile_definitions(needle PRIVATE NEEDLE_JSON_PI=1)
endif()
if(NEEDLE_HIDE_PINGS)
    target_compile_definitions(needle PRIVATE NEEDLE_HIDE_PINGS)
endif()

set(SUBHOOK_STATIC OFF)
set(SUBHOOK_INSTALL OFF)
set(SUBHOOK_TESTS OFF)
set(SUBHOOK_FORCE_32BIT OFF)
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
target_link_libraries(needle PRIVATE pugixml)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp DOWNLOAD_NO_EXTRACT YES)
FetchContent_MakeAvailable(json)
target_include_directories(needle PRIVATE ${json_SOURCE_DIR})