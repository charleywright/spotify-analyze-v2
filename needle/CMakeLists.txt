cmake_minimum_required(VERSION 3.2)
include(FetchContent)
project(needle)

file(GLOB_RECURSE SrcFiles "${CMAKE_CURRENT_SOURCE_DIR}/src/**.cpp")
add_library(needle MODULE ${SrcFiles})
target_link_libraries(needle PRIVATE dl)
set_property(TARGET needle PROPERTY POSITION_IN ON)
set_property(TARGET needle PROPERTY PREFIX "")
set_property(TARGET needle PROPERTY OUTPUT_NAME needle)
set_property(TARGET needle PROPERTY SUFFIX .so)

FetchContent_Declare(subhook
        GIT_REPOSITORY https://github.com/Zeex/subhook
        GIT_TAG e935959d2f9cc642bcbb5e7759b2b1e7196b0947
        )
FetchContent_MakeAvailable(subhook)
target_link_libraries(needle PRIVATE subhook)