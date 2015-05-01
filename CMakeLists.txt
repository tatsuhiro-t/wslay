cmake_minimum_required(VERSION 3.2)

# This CMakeLists.txt file intended for:
# - development of wslay library
# - building wslay for install purposes
# - building wslay with ExternalProject_Add()

if(NOT DEFINED CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif()

project(wslay)

set(INSTALL_INCLUDE_DIR include CACHE PATH
	"Installation directory for header files")
set(INSTALL_LIB_DIR lib CACHE PATH
	"Installation directory for libraries")
set(INSTALL_CMAKE_DIR lib/cmake/wslay CACHE PATH
	"Installation directory for CMake files")
option(WSLAY_CONFIGURE_INSTALL "Generate install target" ON)
option(WSLAY_STATIC "Build static version of the library" ON)
option(WSLAY_SHARED "Build shared version of the library" OFF)

add_subdirectory(lib)

if (WSLAY_CONFIGURE_INSTALL)
    export(EXPORT wslay)
    install(EXPORT wslay
        DESTINATION ${INSTALL_CMAKE_DIR})
    configure_file(wslay-config.cmake.in wslay-config.cmake @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wslay-config.cmake
        DESTINATION ${INSTALL_CMAKE_DIR})
endif()
