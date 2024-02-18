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
# Consider removing this later to test the symbolic executor.
#
add_compile_options(-g -O0)

#
# Add target programs to compile
#
set(DEMO_RTR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/demo-routers)
add_executable(demo-router-1 ${DEMO_RTR_DIR}/r1.cpp)
# add_executable(demo-router-2 ${DEMO_RTR_DIR}/r2.cpp)
# add_executable(demo-router-3 ${DEMO_RTR_DIR}/r3.cpp)
