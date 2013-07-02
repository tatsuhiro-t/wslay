# Source code for tests
set (tests_src
        main.c
        wslay_event_test.c
        wslay_frame_test.c
        wslay_queue_test.c
        wslay_session_test.c
        wslay_stack_test.c)

include_directories (../lib ../lib/includes)

add_executable (tests ${tests_src})
add_dependencies (tests verse_shared_lib)
target_link_libraries (tests
        wslay_shared_lib
        ${CUNIT_LIBRARIES})