cmake_minimum_required(VERSION 3.13)  # CMake version check

project(                              # Create project 
  cicflowmeter-c
  VERSION 0.1.0
  DESCRIPTION "Packet Snipping"
  LANGUAGES C)

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(CICFLOWMETER src)
