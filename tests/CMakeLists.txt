# Source code for tests
set (tests_src
        main.c
        wslay_event_test.c
        wslay_frame_test.c
        wslay_queue_test.c
        wslay_session_test.c
        wslay_stack_test.c)

include_directories (../lib ../lib/include)

# Make build flags compiler specific
if (CMAKE_COMPILER_IS_GNUCC)
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set (CMAKE_C_FLAGS "-ggdb -Wall -Wextra -pedantic -O0 -std=c99")
	elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
		set (CMAKE_C_FLAGS "-DNDEBUG -Wall -Wextra -pedantic -O3 -std=c99")
	endif ()
endif (CMAKE_COMPILER_IS_GNUCC)

add_executable (tests ${tests_src})
add_dependencies (tests verse_shared_lib)
target_link_libraries (tests
        wslay_shared_lib
        ${CUNIT_LIBRARIES})