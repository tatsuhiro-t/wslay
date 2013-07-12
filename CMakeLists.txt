# Minimal version of CMake
cmake_minimum_required (VERSION 2.6)

# Build type
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to 'Release' as none was specified.")
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
	
	# Set the possible values of build type for cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
		"MinSizeRel" "RelWithDebInfo")
endif ()

# Define project name
project (WSLay)

# The version number
set (${PROJECT_NAME}_VERSION_MAJOR 0)
set (${PROJECT_NAME}_VERSION_MINOR 1)
set (${PROJECT_NAME}_PATCH_LEVEL 1)

set (${PROJECT_NAME}_VERSION
	"${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}")

# Build options
option(WSLAY_CLANG "Use Clang Compiler" OFF)
option(WSLAY_CUNIT "CUnit Tests" ON)
option(WSLAY_NETTLE "Nettle Security" ON)
option(WSLAY_SPHINX "Sphinx documentation" ON)

# Clang compiler
if (VERSE_CLANG)
	set (CMAKE_C_COMPILER "/usr/bin/clang")
	set (CMAKE_CC_COMPILER "/usr/bin/clang++")
endif (VERSE_CLANG)

# Set up directory with 3rd party cmake modules
set (CMAKE_MODULE_PATH
	${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build_files/cmake_modules/")

# Set output directory for libraries
set (LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib/)

# Set output directory for binaries
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin/)

# Try to find optional package CUnit
if (WSLAY_CUNIT)
    find_package (CUnit 2.1)
    
    if (CUNIT_FOUND)
        add_subdirectory (tests)
        # Add custom target: make tests
		add_custom_target (test COMMAND "${PROJECT_BINARY_DIR}/bin/tests"
			DEPENDS tests)
    endif (CUNIT_FOUND)
endif (WSLAY_CUNIT)

# Try to find optional package Nettle
if (WSLAY_NETTLE)
    find_package (Nettle)
    
    if (NETTLE_FOUND)
        add_subdirectory (examples)
    endif (NETTLE_FOUND)
endif (WSLAY_NETTLE)

# Try to find sphinx documentation generator
if (WSLAY_SPHINX)
    find_package (Sphinx)
    
    if (SPHINX_EXECUTABLE)
        add_subdirectory (doc/sphinx)
    endif (SPHINX_EXECUTABLE)
endif (WSLAY_SPHINX)

# Generate .h file with current version from template.
# Generating wslayver.h to directory in ${PROJECT_SOURCE_DIR}
# is possible, because wslayver.h is added to .gitignore 
configure_file (
    "${PROJECT_SOURCE_DIR}/lib/include/wslay/wslayver.h.in"
    "${PROJECT_SOURCE_DIR}/lib/include/wslay/wslayver.h" )

# Set up required subdirectories
add_subdirectory (lib)

# Install wslay.h and wslayver.h file
install (DIRECTORY "${PROJECT_SOURCE_DIR}/lib/include/wslay"
	DESTINATION include)

message ("")
message ("* WSLay Configuration *")
message ("")

message (" * Configuration: ${CMAKE_BUILD_TYPE}")

if (CUNIT_FOUND)
	message (" * CUnit:         ON")
else ()
	message (" * CUnit:         OFF")
endif (CUNIT_FOUND)

if (NETTLE_FOUND)
	message (" * Nettle:        ON")
else ()
	message (" * Nettle:        OFF")
endif (NETTLE_FOUND)

if (SPHINX_EXECUTABLE)
	message (" * Sphinx:        ON")
else ()
	message (" * Sphinx:        OFF")
endif (SPHINX_EXECUTABLE)

message ("")