# Source code for examples

set (openssl-echoserv_src openssl-echoserv.c)

include_directories (../../lib/include)

# Make build flags compiler specific
if (CMAKE_COMPILER_IS_GNUCC)
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set (CMAKE_C_FLAGS "-ggdb -Wall -Wextra -pedantic -O0")
	elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
		set (CMAKE_C_FLAGS "-DNDEBUG -Wall -Wextra -pedantic -O3")
	endif ()
endif (CMAKE_COMPILER_IS_GNUCC)

add_executable (openssl-echoserv ${openssl-echoserv_src})
add_dependencies (openssl-echoserv wslay_shared_lib)
target_link_libraries (openssl-echoserv
        wslay_shared_lib
        ${OPENSSL_LIBRARIES})
