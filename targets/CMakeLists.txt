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
    ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# Library sources
#
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
FILE(GLOB_RECURSE LIB_SRCS CONFIGURE_DEPENDS ${LIB_DIR}/*.cpp)

#
# Add target programs to compile
#
set(DEMO_RTR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/demo-routers)
add_executable(demo-router-1 ${DEMO_RTR_DIR}/r1.cpp ${LIB_SRCS})
add_executable(demo-router-2 ${DEMO_RTR_DIR}/r2.cpp ${LIB_SRCS})
add_executable(demo-router-3 ${DEMO_RTR_DIR}/r3.cpp ${LIB_SRCS})

set(HELLO_WORLD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/hello-world)
add_executable(hello-world-1 ${HELLO_WORLD_DIR}/hw1.cpp)
