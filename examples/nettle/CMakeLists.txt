# Source code for examples

set (echoserv_src echoserv.cc)
set (fork-echoserv_src fork-echoserv.c)
set (testclient_src testclient.cc)

include_directories (../../lib/include)

# Make build flags compiler specific
if (CMAKE_COMPILER_IS_GNUCC)
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set (CMAKE_C_FLAGS "-ggdb -Wall -Wextra -pedantic -O0")
	elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
		set (CMAKE_C_FLAGS "-DNDEBUG -Wall -Wextra -pedantic -O3")
	endif ()
endif (CMAKE_COMPILER_IS_GNUCC)

add_executable (echoserv ${echoserv_src})
add_dependencies (echoserv wslay_shared_lib)
target_link_libraries (echoserv
        wslay_shared_lib
        ${NETTLE_LIBRARIES})

add_executable (fork-echoserv ${fork-echoserv_src})
add_dependencies (fork-echoserv wslay_shared_lib)
target_link_libraries (fork-echoserv
        wslay_shared_lib
        ${NETTLE_LIBRARIES})

add_executable (testclient ${testclient_src})
add_dependencies (testclient wslay_shared_lib)
target_link_libraries (testclient
        wslay_shared_lib
        ${NETTLE_LIBRARIES})
