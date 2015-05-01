cmake_minimum_required(VERSION 3.2)

find_package(CUnit REQUIRED)

get_target_property(WSLAY_INCLUDE_DIRS wslay INTERFACE_INCLUDE_DIRECTORIES)
set(WSLAY_DIR ${PROJECT_SOURCE_DIR}/lib)
set(WSLAY_HEADERS
	${WSLAY_DIR}/wslay_event.h
	${WSLAY_DIR}/wslay_frame.h
	${WSLAY_DIR}/wslay_net.h
	${WSLAY_DIR}/wslay_queue.h
	${WSLAY_DIR}/wslay_stack.h)
set(WSLAY_SOURCES
	${WSLAY_DIR}/wslay_event.c
	${WSLAY_DIR}/wslay_frame.c
	${WSLAY_DIR}/wslay_net.c
	${WSLAY_DIR}/wslay_queue.c
	${WSLAY_DIR}/wslay_stack.c)

set(HEADERS
	wslay_event_test.h
	wslay_frame_test.h
	wslay_queue_test.h
	wslay_session_test.h
	wslay_stack_test.h)
set(SOURCES
	wslay_event_test.c
	wslay_frame_test.c
	wslay_queue_test.c
	wslay_session_test.c
	wslay_stack_test.c
	main.c)
add_executable(wslay_tests ${SOURCES} ${HEADERS}
	${WSLAY_SOURCES} ${WSLAY_HEADERS})
target_include_directories(wslay_tests PRIVATE ${WSLAY_DIR} ${WSLAY_INCLUDE_DIRS} ${CUNIT_INCLUDE_DIRS})
target_link_libraries(wslay_tests ${CUNIT_LIBRARIES})
add_dependencies(wslay_tests wslay)
add_test(NAME wslay_tests COMMAND wslay_tests)
