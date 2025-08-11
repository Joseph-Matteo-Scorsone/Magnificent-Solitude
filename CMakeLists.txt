cmake_minimum_required(VERSION 3.10)
project(MagSol VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Header only library
add_library(MagSol INTERFACE)
target_include_directories(MagSol INTERFACE include/)