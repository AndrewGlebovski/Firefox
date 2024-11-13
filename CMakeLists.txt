# Minimum version
cmake_minimum_required(VERSION 3.20)

# Project
project(Firefox VERSION 1.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set C++ flags for build type
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Og -Wall -Wextra -fsanitize=address -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wall -Wextra -Werror -DNDEBUG -s")

# Set include directories
include_directories(sources)

# Parse subdirectories
add_subdirectory(sources)
