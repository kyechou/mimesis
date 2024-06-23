include(CTest)

#
# Get required testing libraries
#
find_package(GTest CONFIG REQUIRED)

#
# Build libps_tests
#
FILE(GLOB_RECURSE LIBPS_TESTS_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libps/*.cpp)
add_executable(libps_tests ${LIBPS_TESTS_SRCS} ${CMAKE_CURRENT_SOURCE_DIR}/util.cpp)
target_include_directories(libps_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(libps_tests PRIVATE
    ps
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    GTest::gmock_main
)
add_test(NAME "libps_tests" COMMAND libps_tests)
set_tests_properties(libps_tests PROPERTIES ENVIRONMENT "DATA_DIR=${CMAKE_CURRENT_SOURCE_DIR}/data")
