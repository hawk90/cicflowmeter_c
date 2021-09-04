cmake_minimum_required(VERSION 3.13)  # CMake version check

project(                              # Create project 
  cicflowmeter-c
  VERSION 0.1.0
  DESCRIPTION "Packet Snipping"
  LANGUAGES C)

set (CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RELEASE)
endif()

include(cmake/FindPCAP.cmake)
include_directories(include)

find_package(Threads)

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(CICFLOWMETER src/cicflowmeter.c)
target_link_libraries(CICFLOWMETER ${PCAP_LIBRARY})
