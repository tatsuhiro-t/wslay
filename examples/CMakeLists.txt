cmake_minimum_required(VERSION 3.2)

include(CheckIncludeFiles)
check_include_files("sys/epoll.h" HAVE_EPOLL)
if(NOT HAVE_EPOLL)
	message(FATAL_ERROR "epoll is required")
endif()
find_package(Nettle REQUIRED)

add_executable(echoserv echoserv.cc)
target_include_directories(echoserv PRIVATE ${NETTLE_INCLUDE_DIRS})
target_link_libraries(echoserv wslay ${NETTLE_LIBRARIES})

add_executable(fork-echoserv fork-echoserv.c)
target_include_directories(fork-echoserv PRIVATE ${NETTLE_INCLUDE_DIRS})
target_link_libraries(fork-echoserv wslay ${NETTLE_LIBRARIES})

add_executable(testclient testclient.cc)
target_include_directories(testclient PRIVATE ${NETTLE_INCLUDE_DIRS})
target_link_libraries(testclient wslay ${NETTLE_LIBRARIES})
