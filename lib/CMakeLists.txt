# Source code for verse library
set (libwslay_src
        wslay_event.c
        wslay_frame.c
        wslay_net.c
        wslay_queue.c
        wslay_stack.c)

include_directories (./include)

# Make build flags compiler specific
if (CMAKE_COMPILER_IS_GNUCC)
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set (CMAKE_C_FLAGS "-D_REETRANT -ggdb -fPIC -Wall -Wextra -pedantic -O0 -std=c99 --coverage")
	elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
		set (CMAKE_C_FLAGS "-D_REETRANT -DNDEBUG -fPIC -Wall -Wextra -pedantic -O3 -std=c99")
	endif ()
endif (CMAKE_COMPILER_IS_GNUCC)


# Set up shared verse library (libwslay.so)
add_library (wslay_shared_lib SHARED ${libwslay_src})
set_target_properties (wslay_shared_lib PROPERTIES
		VERSION "${${PROJECT_NAME}_VERSION}"
		SOVERSION "${${PROJECT_NAME}_VERSION}.${${PROJECT_NAME}_PATCH_LEVEL}"
		OUTPUT_NAME "wslay"
		clean_direct_output 1)

# The rule to install shared library
install (TARGETS wslay_shared_lib
	LIBRARY
	DESTINATION lib${LIBSUFFIX})
