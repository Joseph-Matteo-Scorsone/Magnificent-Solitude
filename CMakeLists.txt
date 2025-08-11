cmake_minimum_required(VERSION 3.10)
project(MagSol VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# interface library
add_library(MagSol INTERFACE)
target_include_directories(MagSol INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(MagSol INTERFACE cxx_std_17)

# sqlite static library
add_library(sqlite3 STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/sqlite/sqlite3.c
)
target_include_directories(sqlite3 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/sqlite
)

# executable
add_executable(magsol_exe src/main.cpp)
target_link_libraries(magsol_exe PRIVATE MagSol sqlite3)
