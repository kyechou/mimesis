#
# Unset compile flags for target programs.
#
unset(CMAKE_C_FLAGS_RELEASE)
unset(CMAKE_CXX_FLAGS_RELEASE)
unset(CMAKE_C_FLAGS_RELWITHDEBINFO)
unset(CMAKE_CXX_FLAGS_RELWITHDEBINFO)
unset(CMAKE_C_FLAGS_DEBUG)
unset(CMAKE_CXX_FLAGS_DEBUG)
unset(CMAKE_EXE_LINKER_FLAGS_DEBUG)

#
# Add debugging compile options for analysis.
# TODO: Remove this later to test the symbolic executor.
#
add_compile_options(-g -O0)

#
# Configure the include directories.
#
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PROJECT_DIR)
cmake_path(SET S2E_GUEST_COMMON_INCLUDE_DIR "${PROJECT_DIR}/src/s2e/guest/common/include")
include_directories(
    ${S2E_GUEST_COMMON_INCLUDE_DIR}
)

#
# Add target programs to compile
#
set(DEMO_RTR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/demo-routers)
FILE(GLOB_RECURSE DEMO_RTR_SRCS CONFIGURE_DEPENDS ${DEMO_RTR_DIR}/*.cpp)
foreach(RTR_SRC ${DEMO_RTR_SRCS})
    get_filename_component(STEM ${RTR_SRC} NAME_WE)
    add_executable(demo-${STEM} ${RTR_SRC} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_net>)
    target_link_libraries(demo-${STEM} PRIVATE _logger _net)
endforeach()

set(HELLO_WORLD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/hello-world)
add_executable(hello-world-1 ${HELLO_WORLD_DIR}/hw1.cpp)
