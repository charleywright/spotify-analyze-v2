cmake_minimum_required(VERSION 3.2)
project(shannon-test)

add_executable(${PROJECT_NAME}
  ShannonTest.c
  ShannonFast.c
  hexlib.c
)

add_executable(shannon-test2
        ShannonTest2.c
#        ShannonFast.c # We include it ourselves...
)

add_library(shannon SHARED Shannon.h ShannonFast.c)
set(Shannon_LIBRARIES shannon PARENT_SCOPE)
set(Shannon_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)