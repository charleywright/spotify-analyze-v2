cmake_minimum_required(VERSION 3.25)
project(shannon-test)

add_executable(${PROJECT_NAME}
  ShannonTest.c
  ShannonFast.c
  hexlib.c
)
