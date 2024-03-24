include(CTest)

#
# Get required testing libraries
#
find_package(GTest REQUIRED)

#
# Build libps_tests
#
FILE(GLOB_RECURSE LIBPS_TESTS_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libps/*.cpp)
add_executable(libps_tests ${LIBPS_TESTS_SRCS})
target_link_libraries(libps_tests PRIVATE
    ps
    gtest::gtest
)
add_test(NAME "libps_tests" COMMAND libps_tests)
