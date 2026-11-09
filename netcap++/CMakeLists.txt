cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)


if(WIN32)
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# set(BUILD_SHARED_LIBS ON)
# set(PCAPPP_INSTALL ON)
add_subdirectory(extern)

project(network-capture)
add_subdirectory(src)

add_subdirectory(python)
