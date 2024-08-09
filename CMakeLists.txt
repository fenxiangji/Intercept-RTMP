cmake_minimum_required(VERSION 3.10)
project(MyProject)

# Set the source directory
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Get all the C++ source files in the source directory
file(GLOB_RECURSE CPP_SOURCES ${SRC_DIR}/*.cpp)

# Add the source files to the project
add_executable(MyProject ${CPP_SOURCES})

# Include the headers in the source directory
target_include_directories(MyProject PRIVATE 
    ${CMAKE_SOURCE_DIR}/../npcap-sdk-1.13/include
)

# Link the libraries
target_link_libraries(MyProject PRIVATE 
    ${CMAKE_SOURCE_DIR}/../npcap-sdk-1.13/lib/x64/Packet.lib
    ${CMAKE_SOURCE_DIR}/../npcap-sdk-1.13/lib/x64/wpcap.lib
    ${CMAKE_SOURCE_DIR}/../npcap-sdk-1.13/lib/x64/wpcap.lib
)