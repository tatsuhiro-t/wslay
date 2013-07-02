# Minimal version of CMake
cmake_minimum_required (VERSION 2.6)

# Build type
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)

	message(STATUS "Setting build type to 'Debug' as none was specified.")
	set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
	
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

# Set output directory for libraries
set (LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib/)

# Set output directory for binaries
#set (EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin/)

# Set up required subdirectories
add_subdirectory (lib)
#add_subdirectory (example)
